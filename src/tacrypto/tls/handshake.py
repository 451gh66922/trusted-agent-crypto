"""Peer-symmetric simplified handshake helper (Host-side, uses SE for ECDHE)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from tacrypto.base import CryptoSuite
from tacrypto.se.client import SeClient
from tacrypto.tls.exporter import tls_exporter
from tacrypto.tls.hkdf_label import derive_secret
from tacrypto.tls.key_schedule import (
    KeySchedule,
    KeyScheduleResult,
    verify_data,
)
from tacrypto.tls.messages import (
    Certificate,
    CertificateVerify,
    ClientHello,
    EncryptedExtensions,
    Finished,
    ServerHello,
)
from tacrypto.tls.traffic import TrafficKeys, traffic_keys
from tacrypto.tls.transcript import TranscriptHash
from tacrypto.types import KeyPair


@dataclass(frozen=True, slots=True)
class PeerTrafficMaterial:
    handshake_client: TrafficKeys
    handshake_server: TrafficKeys
    application_client: TrafficKeys
    application_server: TrafficKeys


@dataclass(frozen=True, slots=True)
class SimplifiedHandshakeResult:
    shared_secret: bytes
    schedule: KeyScheduleResult
    traffic: PeerTrafficMaterial
    exporter_master_secret: bytes
    client_finished_verify: bytes
    server_finished_verify: bytes
    transcript_hash_hello: bytes
    transcript_hash_server_finished: bytes
    transcript_hash_client_finished: bytes


def run_simplified_handshake(
    suite: CryptoSuite,
    *,
    se: SeClient | None = None,
    client_random: bytes | None = None,
    server_random: bytes | None = None,
    server_identity: KeyPair | None = None,
    exporter_label: str = "ta demo",
    exporter_context: bytes = b"merchant-session",
    exporter_length: int = 32,
) -> tuple[SimplifiedHandshakeResult, bytes, bytes]:
    """Run a PSK-less simplified handshake; return result + matching exporters.

    If ``se`` is provided, the **client** ECDHE private key stays in the SE.
    The server ephemeral key is generated in software (merchant Host).
    """
    client_random = client_random or os.urandom(32)
    server_random = server_random or os.urandom(32)
    server_identity = server_identity or suite.generate_signing_keypair()

    client_sk: bytes | None = None
    client_key_id: int | None = None
    if se is not None:
        client_eph = se.gen_ephemeral_key()
        client_share = client_eph.public_key
        client_key_id = client_eph.key_id
    else:
        client_pair = suite.generate_ephemeral_keypair()
        client_share = client_pair.public_key
        client_sk = client_pair.private_key

    server_pair = suite.generate_ephemeral_keypair()
    server_share = server_pair.public_key

    ch = ClientHello(random=client_random, key_share=client_share)
    sh = ServerHello(random=server_random, key_share=server_share)

    transcript = TranscriptHash(suite)
    transcript.update(ch.encode())
    transcript.update(sh.encode())
    th_hello = transcript.digest()

    if se is not None:
        assert client_key_id is not None
        handle = se.ecdh(client_key_id, server_share)
        shared = se.export_secret(handle)
        shared_server = suite.derive_shared_secret(server_pair.private_key, client_share)
        if shared != shared_server:
            raise RuntimeError("ECDHE shared secret mismatch between SE client and server")
    else:
        assert client_sk is not None
        shared = suite.derive_shared_secret(client_sk, server_share)

    schedule = KeySchedule(suite)
    schedule.derive_early_secret()
    hs_secrets = schedule.derive_handshake_secrets(shared, th_hello)

    ee = EncryptedExtensions()
    cert = Certificate(leaf=server_identity.public_key)
    transcript.update(ee.encode())
    transcript.update(cert.encode())
    to_sign = transcript.digest()
    signature = suite.sign(server_identity.private_key, to_sign)
    cv = CertificateVerify(signature=signature)
    transcript.update(cv.encode())
    th_before_server_finished = transcript.digest()
    server_finished_vd = verify_data(
        suite,
        hs_secrets.server_handshake_traffic_secret,
        th_before_server_finished,
    )
    sf = Finished(verify_data=server_finished_vd)
    transcript.update(sf.encode())
    th_server_finished = transcript.digest()

    app = schedule.derive_application_secrets(th_server_finished)

    client_finished_vd = verify_data(
        suite,
        hs_secrets.client_handshake_traffic_secret,
        th_server_finished,
    )
    cf = Finished(verify_data=client_finished_vd)
    transcript.update(cf.encode())
    th_client_finished = transcript.digest()

    resumption = derive_secret(
        suite,
        schedule.master_secret,
        "res master",
        th_client_finished,
        messages_already_hashed=True,
    )
    schedule.resumption_master_secret = resumption
    app = type(app)(
        master_secret=app.master_secret,
        client_application_traffic_secret=app.client_application_traffic_secret,
        server_application_traffic_secret=app.server_application_traffic_secret,
        exporter_master_secret=app.exporter_master_secret,
        resumption_master_secret=resumption,
    )

    result = SimplifiedHandshakeResult(
        shared_secret=shared,
        schedule=KeyScheduleResult(handshake=hs_secrets, application=app),
        traffic=PeerTrafficMaterial(
            handshake_client=traffic_keys(
                suite, hs_secrets.client_handshake_traffic_secret
            ),
            handshake_server=traffic_keys(
                suite, hs_secrets.server_handshake_traffic_secret
            ),
            application_client=traffic_keys(
                suite, app.client_application_traffic_secret
            ),
            application_server=traffic_keys(
                suite, app.server_application_traffic_secret
            ),
        ),
        exporter_master_secret=app.exporter_master_secret,
        client_finished_verify=client_finished_vd,
        server_finished_verify=server_finished_vd,
        transcript_hash_hello=th_hello,
        transcript_hash_server_finished=th_server_finished,
        transcript_hash_client_finished=th_client_finished,
    )

    exp_client = tls_exporter(
        suite, app.exporter_master_secret, exporter_label, exporter_context, exporter_length
    )
    exp_server = tls_exporter(
        suite, app.exporter_master_secret, exporter_label, exporter_context, exporter_length
    )
    return result, exp_client, exp_server
