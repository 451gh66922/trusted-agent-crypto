"""TLS 1.3 Key Schedule (RFC 8446 §7.1) for the (EC)DHE handshake path."""

from __future__ import annotations

from dataclasses import dataclass

from tacrypto.base import CryptoSuite
from tacrypto.tls.hkdf_label import derive_secret, hkdf_expand_label


@dataclass(frozen=True, slots=True)
class HandshakeSecrets:
    early_secret: bytes
    handshake_secret: bytes
    client_handshake_traffic_secret: bytes
    server_handshake_traffic_secret: bytes


@dataclass(frozen=True, slots=True)
class ApplicationSecrets:
    master_secret: bytes
    client_application_traffic_secret: bytes
    server_application_traffic_secret: bytes
    exporter_master_secret: bytes
    resumption_master_secret: bytes


@dataclass(frozen=True, slots=True)
class KeyScheduleResult:
    handshake: HandshakeSecrets
    application: ApplicationSecrets


class KeySchedule:
    """Stateful TLS 1.3 key schedule (PSK-less / (EC)DHE path)."""

    def __init__(self, suite: CryptoSuite) -> None:
        self.suite = suite
        self.hash_len = len(suite.hash(b""))
        self._zeros = b"\x00" * self.hash_len
        self.early_secret = b""
        self.handshake_secret = b""
        self.master_secret = b""
        self.client_handshake_traffic_secret = b""
        self.server_handshake_traffic_secret = b""
        self.client_application_traffic_secret = b""
        self.server_application_traffic_secret = b""
        self.exporter_master_secret = b""
        self.resumption_master_secret = b""

    def derive_early_secret(self, psk: bytes | None = None) -> bytes:
        """``HKDF-Extract(0, PSK)`` — PSK defaults to Hash.length zeros."""
        # RFC 8446: if PSK is not in use, it is replaced with zeros of Hash.length.
        ikm = self._zeros if psk is None else psk
        self.early_secret = self.suite.hkdf_extract(b"", ikm)
        return self.early_secret

    def derive_handshake_secrets(
        self,
        shared_secret: bytes,
        transcript_hash_hello: bytes,
    ) -> HandshakeSecrets:
        """Advance Early → Handshake and derive handshake traffic secrets.

        ``transcript_hash_hello`` = Transcript-Hash(ClientHello || ServerHello).
        """
        if not self.early_secret:
            self.derive_early_secret()
        derived = derive_secret(
            self.suite,
            self.early_secret,
            "derived",
            b"",  # Hash("")
        )
        self.handshake_secret = self.suite.hkdf_extract(derived, shared_secret)
        self.client_handshake_traffic_secret = derive_secret(
            self.suite,
            self.handshake_secret,
            "c hs traffic",
            transcript_hash_hello,
            messages_already_hashed=True,
        )
        self.server_handshake_traffic_secret = derive_secret(
            self.suite,
            self.handshake_secret,
            "s hs traffic",
            transcript_hash_hello,
            messages_already_hashed=True,
        )
        return HandshakeSecrets(
            early_secret=self.early_secret,
            handshake_secret=self.handshake_secret,
            client_handshake_traffic_secret=self.client_handshake_traffic_secret,
            server_handshake_traffic_secret=self.server_handshake_traffic_secret,
        )

    def derive_application_secrets(
        self,
        transcript_hash_server_finished: bytes,
        transcript_hash_client_finished: bytes | None = None,
    ) -> ApplicationSecrets:
        """Advance Handshake → Master and derive application / exporter secrets.

        ``transcript_hash_server_finished`` =
            Transcript-Hash(ClientHello ... Server Finished)
        used for ``c ap traffic``, ``s ap traffic``, ``exp master``.

        ``transcript_hash_client_finished`` =
            Transcript-Hash(... Client Finished) used for ``res master``.
            Defaults to ``transcript_hash_server_finished`` if omitted
            (acceptable when client Finished is not yet in the simulation).
        """
        if not self.handshake_secret:
            raise RuntimeError("handshake secrets must be derived first")
        derived = derive_secret(self.suite, self.handshake_secret, "derived", b"")
        self.master_secret = self.suite.hkdf_extract(derived, self._zeros)
        th_sf = transcript_hash_server_finished
        self.client_application_traffic_secret = derive_secret(
            self.suite,
            self.master_secret,
            "c ap traffic",
            th_sf,
            messages_already_hashed=True,
        )
        self.server_application_traffic_secret = derive_secret(
            self.suite,
            self.master_secret,
            "s ap traffic",
            th_sf,
            messages_already_hashed=True,
        )
        self.exporter_master_secret = derive_secret(
            self.suite,
            self.master_secret,
            "exp master",
            th_sf,
            messages_already_hashed=True,
        )
        th_cf = (
            transcript_hash_client_finished
            if transcript_hash_client_finished is not None
            else th_sf
        )
        self.resumption_master_secret = derive_secret(
            self.suite,
            self.master_secret,
            "res master",
            th_cf,
            messages_already_hashed=True,
        )
        return ApplicationSecrets(
            master_secret=self.master_secret,
            client_application_traffic_secret=self.client_application_traffic_secret,
            server_application_traffic_secret=self.server_application_traffic_secret,
            exporter_master_secret=self.exporter_master_secret,
            resumption_master_secret=self.resumption_master_secret,
        )

    def run(
        self,
        shared_secret: bytes,
        transcript_hash_hello: bytes,
        transcript_hash_server_finished: bytes,
        transcript_hash_client_finished: bytes | None = None,
        psk: bytes | None = None,
    ) -> KeyScheduleResult:
        """Full PSK-less (or optional PSK) schedule in one call."""
        self.derive_early_secret(psk)
        hs = self.derive_handshake_secrets(shared_secret, transcript_hash_hello)
        app = self.derive_application_secrets(
            transcript_hash_server_finished,
            transcript_hash_client_finished,
        )
        return KeyScheduleResult(handshake=hs, application=app)


def finished_key(suite: CryptoSuite, base_key: bytes) -> bytes:
    """``finished_key = HKDF-Expand-Label(BaseKey, \"finished\", \"\", Hash.length)``."""
    hash_len = len(suite.hash(b""))
    return hkdf_expand_label(suite, base_key, "finished", b"", hash_len)


def verify_data(suite: CryptoSuite, base_key: bytes, transcript_hash: bytes) -> bytes:
    """Finished verify_data = HMAC(finished_key, Transcript-Hash)."""
    return suite.hmac(finished_key(suite, base_key), transcript_hash)
