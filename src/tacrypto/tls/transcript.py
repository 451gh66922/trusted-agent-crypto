"""Transcript-Hash for TLS 1.3 (RFC 8446 §4.4.1)."""

from __future__ import annotations

from tacrypto.base import CryptoSuite


class TranscriptHash:
    """Incremental transcript: ``Hash(M1 || M2 || ... || Mn)``."""

    def __init__(self, suite: CryptoSuite) -> None:
        self._suite = suite
        self._buffer = bytearray()

    def update(self, message: bytes) -> None:
        self._buffer.extend(message)

    def digest(self) -> bytes:
        return self._suite.hash(bytes(self._buffer))

    def clone(self) -> TranscriptHash:
        other = TranscriptHash(self._suite)
        other._buffer = bytearray(self._buffer)
        return other

    @property
    def messages(self) -> bytes:
        return bytes(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)
