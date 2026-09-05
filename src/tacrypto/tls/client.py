"""Independent TLS client state machine (Host + optional SE for ECDHE)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from tacrypto.base import CryptoSuite
from tacrypto.se.client import SeClient
from tacrypto.tls.alert import AlertDescription, AlertLevel, encode_alert, parse_alert
from tacrypto.tls.exporter import tls_exporter
from tacrypto.tls.hkdf_label import derive_secret
from tacrypto.tls.key_schedule import KeySchedule, verify_data
from tacrypto.tls.messages import (
    Certificate,
    CertificateVerify,
    ClientHello,
    Finished,
    HandshakeType,
    ServerHello,
    iter_handshake_messages,
    parse_certificate,
    parse_certificate_verify,
    parse_finished,
    parse_server_hello,
)
from tacrypto.tls.record import ContentType, RecordLayer
from tacrypto.tls.state import (
    HandshakeState,
    TlsError,
    derive_channel_binding,
)
from tacrypto.tls.traffic import traffic_keys
from tacrypto.tls.transcript import TranscriptHash


@dataclass
class TlsClient:
    """SE-backed (or software) TLS client peer.

    Wire I/O is explicit: callers pass/receive record bytes. No shared
    memory with ``MerchantServer``.
    """

    suite: CryptoSuite
    se: SeClient | None = None
    state: HandshakeState = HandshakeState.INIT
    transcript: TranscriptHash = field(init=False)
    schedule: KeySchedule = field(init=False)
    records: RecordLayer = field(init=False)
    client_random: bytes = field(default_factory=lambda: os.urandom(32))
    _client_share: bytes = b""
    _client_key_id: int | None = None
    _client_sk: bytes | None = None
    _shared_secret: bytes = b""
    _server_identity_pk: bytes = b""
    exporter_master_secret: bytes = b""
    channel_binding: bytes = b""
    _pending_client_finished: bytes = b""

    def __post_init__(self) -> None:
        self.transcript = TranscriptHash(self.suite)
        self.schedule = KeySchedule(self.suite)
        self.records = RecordLayer(self.suite)

    # --- handshake ---------------------------------------------------------

    def start_handshake(self) -> bytes:
        """Build ClientHello record (plaintext)."""
        if self.state != HandshakeState.INIT:
            raise TlsError(f"cannot start handshake from {self.state}")
        if self.se is not None:
            eph = self.se.gen_ephemeral_key()
            self._client_share = eph.public_key
            self._client_key_id = eph.key_id
        else:
            pair = self.suite.generate_ephemeral_keypair()
            self._client_share = pair.public_key
            self._client_sk = pair.private_key
        ch = ClientHello(random=self.client_random, key_share=self._client_share)
        encoded = ch.encode()
        self.transcript.update(encoded)
        self.state = HandshakeState.WAIT_SERVER_HELLO
        return self.records.write_plaintext(ContentType.HANDSHAKE, encoded)

    def handle_server_hello(self, record: bytes) -> None:
        if self.state != HandshakeState.WAIT_SERVER_HELLO:
            raise TlsError(f"unexpected ServerHello in {self.state}")
        ctype, fragment, rest = self.records.read_plaintext(record)
        if rest or ctype != ContentType.HANDSHAKE:
            raise TlsError("expected a single handshake plaintext record")
        sh = parse_server_hello(fragment)
        self.transcript.update(fragment)
        th_hello = self.transcript.digest()

        if self.se is not None:
            assert self._client_key_id is not None
            handle = self.se.ecdh(self._client_key_id, sh.key_share)
            self._shared_secret = self.se.export_secret(handle)
        else:
            assert self._client_sk is not None
            self._shared_secret = self.suite.derive_shared_secret(
                self._client_sk, sh.key_share
            )

        self.schedule.derive_early_secret()
        hs = self.schedule.derive_handshake_secrets(self._shared_secret, th_hello)
        # Client read = server handshake write; client write = client hs write
        self.records.install_keys(
            read=traffic_keys(self.suite, hs.server_handshake_traffic_secret),
            write=traffic_keys(self.suite, hs.client_handshake_traffic_secret),
        )
        self.state = HandshakeState.WAIT_SERVER_FLIGHT

    def handle_server_flight(self, record: bytes) -> bytes:
        """Process encrypted server flight; return ClientFinished record."""
        if self.state != HandshakeState.WAIT_SERVER_FLIGHT:
            raise TlsError(f"unexpected server flight in {self.state}")
        ctype, fragment, rest = self.records.open(record)
        if rest:
            raise TlsError("trailing data after server flight record")
        if ctype != ContentType.HANDSHAKE:
            raise TlsError("server flight must be handshake content")

        messages = iter_handshake_messages(fragment)
        expected = [
            HandshakeType.ENCRYPTED_EXTENSIONS,
            HandshakeType.CERTIFICATE,
            HandshakeType.CERTIFICATE_VERIFY,
            HandshakeType.FINISHED,
        ]
        if [t for t, _ in messages] != expected:
            raise TlsError(f"unexpected server flight shape: {[t for t, _ in messages]}")

        ee_msg = messages[0][1]
        cert_msg = messages[1][1]
        cv_msg = messages[2][1]
        fin_msg = messages[3][1]

        self.transcript.update(ee_msg)
        self.transcript.update(cert_msg)
        cert = parse_certificate(cert_msg)
        self._server_identity_pk = cert.leaf
        to_verify = self.transcript.digest()
        cv = parse_certificate_verify(cv_msg)
        if not self.suite.verify(cert.leaf, to_verify, cv.signature):
            raise TlsError("server CertificateVerify failed")
        self.transcript.update(cv_msg)

        th_before_sf = self.transcript.digest()
        sf = parse_finished(fin_msg)
        expected_vd = verify_data(
            self.suite,
            self.schedule.server_handshake_traffic_secret,
            th_before_sf,
        )
        if sf.verify_data != expected_vd:
            raise TlsError("server Finished verify_data mismatch")
        self.transcript.update(fin_msg)
        th_sf = self.transcript.digest()

        app = self.schedule.derive_application_secrets(th_sf)
        self.exporter_master_secret = app.exporter_master_secret

        client_vd = verify_data(
            self.suite,
            self.schedule.client_handshake_traffic_secret,
            th_sf,
        )
        cf = Finished(verify_data=client_vd)
        cf_encoded = cf.encode()
        # Still using handshake keys for ClientFinished
        out = self.records.seal(ContentType.HANDSHAKE, cf_encoded)

        self.transcript.update(cf_encoded)
        th_cf = self.transcript.digest()
        self.schedule.resumption_master_secret = derive_secret(
            self.suite,
            self.schedule.master_secret,
            "res master",
            th_cf,
            messages_already_hashed=True,
        )

        # Switch to application traffic keys
        self.records.install_keys(
            read=traffic_keys(self.suite, app.server_application_traffic_secret),
            write=traffic_keys(self.suite, app.client_application_traffic_secret),
        )
        self.channel_binding = derive_channel_binding(
            self.suite, self.exporter_master_secret
        )
        self.state = HandshakeState.CONNECTED
        return out

    # --- application data --------------------------------------------------

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

    def channel_binding_exporter(self) -> bytes:
        if not self.channel_binding:
            raise TlsError("channel binding not ready")
        return self.channel_binding

    def close(self) -> bytes:
        """Emit encrypted ``close_notify`` and mark CLOSED."""
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
