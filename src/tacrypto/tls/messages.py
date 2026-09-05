"""Normalized handshake messages for the simplified TLS 1.3 simulation.

Wire format is intentionally simple and deterministic (length-prefixed fields).
For RFC 8448 KATs, callers may feed raw handshake bytes into ``TranscriptHash``
directly instead of using these helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class HandshakeType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_VERIFY = 15
    FINISHED = 20


def _u16(n: int) -> bytes:
    if not (0 <= n <= 0xFFFF):
        raise ValueError("uint16 out of range")
    return n.to_bytes(2, "big")


def _u24(n: int) -> bytes:
    if not (0 <= n <= 0xFFFFFF):
        raise ValueError("uint24 out of range")
    return n.to_bytes(3, "big")


def _opaque16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _opaque24(data: bytes) -> bytes:
    return _u24(len(data)) + data


def wrap_handshake(msg_type: HandshakeType, body: bytes) -> bytes:
    """TLS-style handshake header: type(1) + length(3) + body."""
    return bytes((int(msg_type),)) + _u24(len(body)) + body


@dataclass(frozen=True, slots=True)
class ClientHello:
    """Normalized ClientHello used by the simulation."""

    random: bytes
    key_share: bytes
    cipher_suite: bytes = b"\x13\x01"  # TLS_AES_128_GCM_SHA256
    legacy_version: bytes = b"\x03\x03"

    def __post_init__(self) -> None:
        if len(self.random) != 32:
            raise ValueError("ClientHello.random must be 32 bytes")
        if len(self.legacy_version) != 2:
            raise ValueError("legacy_version must be 2 bytes")
        if len(self.cipher_suite) != 2:
            raise ValueError("cipher_suite must be 2 bytes")

    def body(self) -> bytes:
        return (
            self.legacy_version
            + self.random
            + self.cipher_suite
            + _opaque16(self.key_share)
        )

    def encode(self) -> bytes:
        return wrap_handshake(HandshakeType.CLIENT_HELLO, self.body())


@dataclass(frozen=True, slots=True)
class ServerHello:
    random: bytes
    key_share: bytes
    cipher_suite: bytes = b"\x13\x01"
    legacy_version: bytes = b"\x03\x03"

    def __post_init__(self) -> None:
        if len(self.random) != 32:
            raise ValueError("ServerHello.random must be 32 bytes")
        if len(self.legacy_version) != 2:
            raise ValueError("legacy_version must be 2 bytes")
        if len(self.cipher_suite) != 2:
            raise ValueError("cipher_suite must be 2 bytes")

    def body(self) -> bytes:
        return (
            self.legacy_version
            + self.random
            + self.cipher_suite
            + _opaque16(self.key_share)
        )

    def encode(self) -> bytes:
        return wrap_handshake(HandshakeType.SERVER_HELLO, self.body())


@dataclass(frozen=True, slots=True)
class EncryptedExtensions:
    extensions: bytes = b""

    def encode(self) -> bytes:
        return wrap_handshake(
            HandshakeType.ENCRYPTED_EXTENSIONS,
            _opaque16(self.extensions),
        )


@dataclass(frozen=True, slots=True)
class Certificate:
    """Simulation certificate: opaque leaf public key / blob."""

    leaf: bytes

    def encode(self) -> bytes:
        return wrap_handshake(HandshakeType.CERTIFICATE, _opaque24(self.leaf))


@dataclass(frozen=True, slots=True)
class CertificateVerify:
    signature: bytes
    scheme: bytes = b"\x04\x03"  # ecdsa_secp256r1_sha256

    def encode(self) -> bytes:
        return wrap_handshake(
            HandshakeType.CERTIFICATE_VERIFY,
            self.scheme + _opaque16(self.signature),
        )


@dataclass(frozen=True, slots=True)
class Finished:
    verify_data: bytes

    def encode(self) -> bytes:
        return wrap_handshake(HandshakeType.FINISHED, self.verify_data)


def split_handshake(raw: bytes) -> tuple[HandshakeType, bytes, bytes]:
    """Split one handshake message; return (type, full_message_bytes, remainder)."""
    if len(raw) < 4:
        raise ValueError("handshake message too short")
    msg_type = HandshakeType(raw[0])
    length = int.from_bytes(raw[1:4], "big")
    if len(raw) < 4 + length:
        raise ValueError("truncated handshake body")
    full = raw[: 4 + length]
    return msg_type, full, raw[4 + length :]


def iter_handshake_messages(raw: bytes) -> list[tuple[HandshakeType, bytes]]:
    out: list[tuple[HandshakeType, bytes]] = []
    rest = raw
    while rest:
        msg_type, full, rest = split_handshake(rest)
        out.append((msg_type, full))
    return out


def parse_client_hello(full: bytes) -> ClientHello:
    msg_type, body_msg, rest = split_handshake(full)
    if rest or msg_type != HandshakeType.CLIENT_HELLO:
        raise ValueError("not a single ClientHello")
    body = body_msg[4:]
    if len(body) < 2 + 32 + 2 + 2:
        raise ValueError("ClientHello body too short")
    legacy_version = body[0:2]
    random = body[2:34]
    cipher_suite = body[34:36]
    share_len = int.from_bytes(body[36:38], "big")
    key_share = body[38 : 38 + share_len]
    if len(key_share) != share_len:
        raise ValueError("truncated key_share")
    return ClientHello(
        random=random,
        key_share=key_share,
        cipher_suite=cipher_suite,
        legacy_version=legacy_version,
    )


def parse_server_hello(full: bytes) -> ServerHello:
    msg_type, body_msg, rest = split_handshake(full)
    if rest or msg_type != HandshakeType.SERVER_HELLO:
        raise ValueError("not a single ServerHello")
    body = body_msg[4:]
    if len(body) < 2 + 32 + 2 + 2:
        raise ValueError("ServerHello body too short")
    legacy_version = body[0:2]
    random = body[2:34]
    cipher_suite = body[34:36]
    share_len = int.from_bytes(body[36:38], "big")
    key_share = body[38 : 38 + share_len]
    if len(key_share) != share_len:
        raise ValueError("truncated key_share")
    return ServerHello(
        random=random,
        key_share=key_share,
        cipher_suite=cipher_suite,
        legacy_version=legacy_version,
    )


def parse_certificate(full: bytes) -> Certificate:
    msg_type, body_msg, rest = split_handshake(full)
    if rest or msg_type != HandshakeType.CERTIFICATE:
        raise ValueError("not a single Certificate")
    body = body_msg[4:]
    leaf_len = int.from_bytes(body[0:3], "big")
    leaf = body[3 : 3 + leaf_len]
    if len(leaf) != leaf_len:
        raise ValueError("truncated certificate leaf")
    return Certificate(leaf=leaf)


def parse_certificate_verify(full: bytes) -> CertificateVerify:
    msg_type, body_msg, rest = split_handshake(full)
    if rest or msg_type != HandshakeType.CERTIFICATE_VERIFY:
        raise ValueError("not a single CertificateVerify")
    body = body_msg[4:]
    scheme = body[0:2]
    sig_len = int.from_bytes(body[2:4], "big")
    signature = body[4 : 4 + sig_len]
    if len(signature) != sig_len:
        raise ValueError("truncated signature")
    return CertificateVerify(signature=signature, scheme=scheme)


def parse_finished(full: bytes) -> Finished:
    msg_type, body_msg, rest = split_handshake(full)
    if rest or msg_type != HandshakeType.FINISHED:
        raise ValueError("not a single Finished")
    return Finished(verify_data=body_msg[4:])
