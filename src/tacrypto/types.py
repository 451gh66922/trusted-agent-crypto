"""Shared types for crypto suites."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Asymmetric key pair in raw / library-native byte encodings.

    Encoding conventions are documented per suite implementation.
    """

    private_key: bytes
    public_key: bytes


@dataclass(frozen=True, slots=True)
class AeadResult:
    """AEAD output: ciphertext concatenated with authentication tag."""

    ciphertext_and_tag: bytes

    @property
    def ciphertext(self) -> bytes:
        if len(self.ciphertext_and_tag) < 16:
            raise ValueError("AEAD payload too short for a 16-byte tag")
        return self.ciphertext_and_tag[:-16]

    @property
    def tag(self) -> bytes:
        if len(self.ciphertext_and_tag) < 16:
            raise ValueError("AEAD payload too short for a 16-byte tag")
        return self.ciphertext_and_tag[-16:]
