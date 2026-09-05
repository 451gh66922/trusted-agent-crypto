"""Independent merchant TLS server state machine."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from tacrypto.base import CryptoSuite
from tacrypto.tls.alert import AlertDescription, AlertLevel, encode_alert, parse_alert
from tacrypto.tls.exporter import tls_exporter
from tacrypto.tls.hkdf_label import derive_secret
from tacrypto.tls.key_schedule import KeySchedule, verify_data
from tacrypto.tls.messages import (
    Certificate,
    CertificateVerify,
    EncryptedExtensions,
    Finished,
    HandshakeType,
    ServerHello,
    iter_handshake_messages,
    parse_client_hello,
    parse_finished,
)
from tacrypto.tls.record import ContentType, RecordLayer
from tacrypto.tls.state import HandshakeState, TlsError, derive_channel_binding
from tacrypto.tls.traffic import TrafficKeys, traffic_keys
from tacrypto.tls.transcript import TranscriptHash
from tacrypto.types import KeyPair


@dataclass
class MerchantServer:
    """Merchant-side TLS peer (software keys; no SE required)."""

    suite: CryptoSuite
    identity: KeyPair | None = None
    state: HandshakeState = HandshakeState.INIT
    server_random: bytes = field(default_factory=lambda: os.urandom(32))
    transcript: TranscriptHash = field(init=False)
    schedule: KeySchedule = field(init=False)
    records: RecordLayer = field(init=False)
    _server_sk: bytes = field(default=b"", init=False, repr=False)
    _server_share: bytes = field(default=b"", init=False)
    _shared_secret: bytes = field(default=b"", init=False, repr=False)
    _app_read: TrafficKeys | None = field(default=None, init=False)
    _app_write: TrafficKeys | None = field(default=None, init=False)
    exporter_master_secret: bytes = field(default=b"", init=False)
    channel_binding: bytes = field(default=b"", init=False)

    def __post_init__(self) -> None:
        if self.identity is None:
            self.identity = self.suite.generate_signing_keypair()
        self.transcript = TranscriptHash(self.suite)
        self.schedule = KeySchedule(self.suite)
        self.records = RecordLayer(self.suite)

    def handle_client_hello(self, record: bytes) -> bytes:
        """Process ClientHello; return ServerHello plaintext record."""
        if self.state != HandshakeState.INIT:
            raise TlsError(f"unexpected ClientHello in {self.state}")
        ctype, fragment, rest = self.records.read_plaintext(record)
        if rest or ctype != ContentType.HANDSHAKE:
            raise TlsError("expected a single handshake plaintext record")
        ch = parse_client_hello(fragment)
        self.transcript.update(fragment)

        eph = self.suite.generate_ephemeral_keypair()
        self._server_sk = eph.private_key
        self._server_share = eph.public_key
        self._shared_secret = self.suite.derive_shared_secret(
            self._server_sk, ch.key_share
        )

        sh = ServerHello(random=self.server_random, key_share=self._server_share)
        sh_encoded = sh.encode()
        self.transcript.update(sh_encoded)
        th_hello = self.transcript.digest()

        self.schedule.derive_early_secret()
        hs = self.schedule.derive_handshake_secrets(self._shared_secret, th_hello)
        self.records.install_keys(
            write=traffic_keys(self.suite, hs.server_handshake_traffic_secret),
            read=traffic_keys(self.suite, hs.client_handshake_traffic_secret),
        )
        self.state = HandshakeState.WAIT_CLIENT_FINISHED
        return self.records.write_plaintext(ContentType.HANDSHAKE, sh_encoded)

    def build_server_flight(self) -> bytes:
        """EncryptedExtensions + Certificate + CertificateVerify + Finished."""
        if self.state != HandshakeState.WAIT_CLIENT_FINISHED:
            raise TlsError(f"cannot build server flight in {self.state}")
        assert self.identity is not None

        ee = EncryptedExtensions().encode()
        cert = Certificate(leaf=self.identity.public_key).encode()
        self.transcript.update(ee)
        self.transcript.update(cert)
        to_sign = self.transcript.digest()
        signature = self.suite.sign(self.identity.private_key, to_sign)
        cv = CertificateVerify(signature=signature).encode()
        self.transcript.update(cv)

        th_before_sf = self.transcript.digest()
        sf_vd = verify_data(
            self.suite,
            self.schedule.server_handshake_traffic_secret,
            th_before_sf,
        )
        sf = Finished(verify_data=sf_vd).encode()
        self.transcript.update(sf)
        th_sf = self.transcript.digest()

        app = self.schedule.derive_application_secrets(th_sf)
        self.exporter_master_secret = app.exporter_master_secret
        self._app_read = traffic_keys(
            self.suite, app.client_application_traffic_secret
        )
        self._app_write = traffic_keys(
            self.suite, app.server_application_traffic_secret
        )

        flight = ee + cert + cv + sf
        return self.records.seal(ContentType.HANDSHAKE, flight)

    def handle_client_finished(self, record: bytes) -> None:
        if self.state != HandshakeState.WAIT_CLIENT_FINISHED:
            raise TlsError(f"unexpected ClientFinished in {self.state}")
        ctype, fragment, rest = self.records.open(record)
        if rest or ctype != ContentType.HANDSHAKE:
            raise TlsError("expected handshake ClientFinished record")
        msgs = iter_handshake_messages(fragment)
        if len(msgs) != 1 or msgs[0][0] != HandshakeType.FINISHED:
            raise TlsError("expected a single Finished")
        cf = parse_finished(msgs[0][1])
        expected = verify_data(
            self.suite,
            self.schedule.client_handshake_traffic_secret,
            self.transcript.digest(),
        )
        if cf.verify_data != expected:
            raise TlsError("client Finished verify_data mismatch")
        self.transcript.update(msgs[0][1])
        th_cf = self.transcript.digest()
        self.schedule.resumption_master_secret = derive_secret(
            self.suite,
            self.schedule.master_secret,
            "res master",
            th_cf,
            messages_already_hashed=True,
        )
        assert self._app_read is not None and self._app_write is not None
        self.records.install_keys(read=self._app_read, write=self._app_write)
        self.channel_binding = derive_channel_binding(
            self.suite, self.exporter_master_secret
        )
        self.state = HandshakeState.CONNECTED

    def send_app_data(self, payload: bytes, *, padding: int = 0) -> bytes:
        if self.state != HandshakeState.CONNECTED:
            raise TlsError("not connected")
        return self.records.seal(ContentType.APPLICATION_DATA, payload, padding=padding)

    def recv_app_data(self, record: bytes) -> bytes:
        if self.state != HandshakeState.CONNECTED:
            raise TlsError("not connected")
        ctype, content, rest = self.records.open(record)
        if rest:
            raise TlsError("trailing data after app record")
        if ctype != ContentType.APPLICATION_DATA:
            raise TlsError(f"expected application_data, got {ctype}")
        return content

    def exporter(self, label: str, context: bytes, length: int = 32) -> bytes:
        if not self.exporter_master_secret:
            raise TlsError("exporter not available yet")
        return tls_exporter(
            self.suite, self.exporter_master_secret, label, context, length
        )

    def close(self) -> bytes:
        if self.state == HandshakeState.CLOSED:
            return b""
        if self.state != HandshakeState.CONNECTED:
            self.state = HandshakeState.CLOSED
            return b""
        payload = encode_alert(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY)
        wire = self.records.seal(ContentType.ALERT, payload)
        self.state = HandshakeState.CLOSED
        return wire

    def handle_alert(self, record: bytes) -> tuple[AlertLevel, AlertDescription]:
        ctype, content, rest = self.records.open(record)
        if rest or ctype != ContentType.ALERT:
            raise TlsError("expected alert record")
        level, desc = parse_alert(content)
        if desc == AlertDescription.CLOSE_NOTIFY:
            self.state = HandshakeState.CLOSED
        return level, desc
