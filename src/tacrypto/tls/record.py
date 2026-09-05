"""TLS 1.3 record layer with formal framing (RFC 8446 §5).

Plaintext records (handshake before keys):
  type(1) || legacy_record_version(2)=0x0303 || length(2) || fragment

Encrypted records (TLSCiphertext):
  outer type = application_data (23)
  AEAD plaintext = TLSInnerPlaintext = content || real_type || zero padding
  AEAD AAD = outer header (type || version || length) where length covers
  ciphertext || tag.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from tacrypto.base import CryptoSuite
from tacrypto.tls.traffic import TrafficKeys

LEGACY_RECORD_VERSION = b"\x03\x03"
TAG_LEN = 16
MAX_FRAGMENT = 16384


class ContentType(IntEnum):
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class RecordError(ValueError):
    """Malformed or authenticating-failed TLS record."""


@dataclass(frozen=True, slots=True)
class TLSPlaintext:
    content_type: ContentType
    fragment: bytes

    def encode(self) -> bytes:
        if len(self.fragment) > MAX_FRAGMENT:
            raise RecordError("fragment too large")
        return (
            bytes((int(self.content_type),))
            + LEGACY_RECORD_VERSION
            + len(self.fragment).to_bytes(2, "big")
            + self.fragment
        )


def parse_plaintext(raw: bytes) -> tuple[TLSPlaintext, bytes]:
    """Parse one plaintext record; return (record, remainder)."""
    if len(raw) < 5:
        raise RecordError("truncated record header")
    ctype = ContentType(raw[0])
    version = raw[1:3]
    length = int.from_bytes(raw[3:5], "big")
    if version != LEGACY_RECORD_VERSION:
        raise RecordError(f"unexpected legacy_record_version {version!r}")
    if length > MAX_FRAGMENT:
        raise RecordError("declared length too large")
    if len(raw) < 5 + length:
        raise RecordError("truncated record body")
    fragment = raw[5 : 5 + length]
    return TLSPlaintext(ctype, fragment), raw[5 + length :]


def nonce_for_sequence(iv: bytes, sequence: int) -> bytes:
    """TLS 1.3 nonce: IV XOR left-padded 64-bit sequence (RFC 8446 §5.3)."""
    if len(iv) != 12:
        raise ValueError("AES-GCM IV must be 12 bytes")
    if sequence < 0 or sequence >= (1 << 64):
        raise ValueError("sequence out of range")
    padded = b"\x00" * 4 + sequence.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, padded, strict=True))


def build_inner_plaintext(content: bytes, content_type: ContentType, padding: int = 0) -> bytes:
    if padding < 0:
        raise ValueError("padding must be non-negative")
    return content + bytes((int(content_type),)) + (b"\x00" * padding)


def parse_inner_plaintext(inner: bytes) -> tuple[bytes, ContentType]:
    """Strip trailing zero padding and extract the real content type byte."""
    if not inner:
        raise RecordError("empty inner plaintext")
    end = len(inner) - 1
    while end >= 0 and inner[end] == 0:
        end -= 1
    if end < 0:
        raise RecordError("inner plaintext is all padding")
    content_type = ContentType(inner[end])
    return inner[:end], content_type


@dataclass
class RecordLayer:
    """Per-direction sequence counters for one traffic key epoch."""

    suite: CryptoSuite
    read_keys: TrafficKeys | None = None
    write_keys: TrafficKeys | None = None
    read_seq: int = 0
    write_seq: int = 0

    def reset_sequences(self) -> None:
        self.read_seq = 0
        self.write_seq = 0

    def install_keys(self, *, read: TrafficKeys | None = None, write: TrafficKeys | None = None) -> None:
        if read is not None:
            self.read_keys = read
            self.read_seq = 0
        if write is not None:
            self.write_keys = write
            self.write_seq = 0

    def write_plaintext(self, content_type: ContentType, fragment: bytes) -> bytes:
        return TLSPlaintext(content_type, fragment).encode()

    def read_plaintext(self, raw: bytes) -> tuple[ContentType, bytes, bytes]:
        rec, rest = parse_plaintext(raw)
        return rec.content_type, rec.fragment, rest

    def seal(
        self,
        content_type: ContentType,
        content: bytes,
        *,
        padding: int = 0,
    ) -> bytes:
        """Encrypt one record; return full TLSCiphertext bytes."""
        if self.write_keys is None:
            raise RecordError("write keys not installed")
        if len(content) > MAX_FRAGMENT:
            raise RecordError("content too large")
        inner = build_inner_plaintext(content, content_type, padding)
        # length field covers ciphertext || tag
        opaque_len = len(inner) + TAG_LEN
        header = (
            bytes((int(ContentType.APPLICATION_DATA),))
            + LEGACY_RECORD_VERSION
            + opaque_len.to_bytes(2, "big")
        )
        nonce = nonce_for_sequence(self.write_keys.iv, self.write_seq)
        sealed = self.suite.aead_encrypt(self.write_keys.key, nonce, inner, header)
        self.write_seq += 1
        return header + sealed

    def open(self, raw: bytes) -> tuple[ContentType, bytes, bytes]:
        """Decrypt one TLSCiphertext; return (type, content, remainder)."""
        if self.read_keys is None:
            raise RecordError("read keys not installed")
        if len(raw) < 5 + TAG_LEN:
            raise RecordError("truncated ciphertext record")
        if raw[0] != int(ContentType.APPLICATION_DATA):
            raise RecordError("encrypted record must have outer type application_data")
        if raw[1:3] != LEGACY_RECORD_VERSION:
            raise RecordError("unexpected legacy_record_version")
        length = int.from_bytes(raw[3:5], "big")
        if length < TAG_LEN or length > MAX_FRAGMENT + 256:
            raise RecordError("invalid ciphertext length")
        if len(raw) < 5 + length:
            raise RecordError("truncated ciphertext body")
        header = raw[:5]
        sealed = raw[5 : 5 + length]
        rest = raw[5 + length :]
        nonce = nonce_for_sequence(self.read_keys.iv, self.read_seq)
        try:
            inner = self.suite.aead_decrypt(self.read_keys.key, nonce, sealed, header)
        except ValueError as exc:
            raise RecordError("AEAD authentication failed") from exc
        self.read_seq += 1
        content, ctype = parse_inner_plaintext(inner)
        return ctype, content, rest


# --- Back-compat thin helpers (payload-only AEAD, no framing) ---------------

def seal(
    suite: CryptoSuite,
    keys: TrafficKeys,
    plaintext: bytes,
    *,
    sequence: int,
    aad: bytes = b"",
) -> bytes:
    """Legacy helper: encrypt payload only (no record header)."""
    nonce = nonce_for_sequence(keys.iv, sequence)
    return suite.aead_encrypt(keys.key, nonce, plaintext, aad)


def open(
    suite: CryptoSuite,
    keys: TrafficKeys,
    data: bytes,
    *,
    sequence: int,
    aad: bytes = b"",
) -> bytes:
    """Legacy helper: decrypt payload only (no record header)."""
    nonce = nonce_for_sequence(keys.iv, sequence)
    return suite.aead_decrypt(keys.key, nonce, data, aad)
