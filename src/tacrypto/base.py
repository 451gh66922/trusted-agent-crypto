"""Abstract crypto suite interface used by SE / TLS simulation layers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from tacrypto.types import KeyPair


@runtime_checkable
class CryptoSuite(Protocol):
    """Unified primitive surface for international and GM backends.
    """

    @property
    def name(self) -> str:
        """Suite id: ``\"intl\"`` or ``\"gm\"``."""
        ...

    # --- Hash / MAC / KDF -------------------------------------------------

    def hash(self, data: bytes) -> bytes:
        """Hash ``data`` (intl: SHA-256; gm: SM3)."""
        ...

    def hmac(self, key: bytes, data: bytes) -> bytes:
        """HMAC with the suite hash (intl: HMAC-SHA256)."""
        ...

    def hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract (RFC 5869). Empty salt means HashLen zero bytes."""
        ...

    def hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand (RFC 5869) to ``length`` bytes."""
        ...

    # --- AEAD -------------------------------------------------------------

    def aead_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """Encrypt and authenticate; return ``ciphertext || tag`` (tag 16 bytes)."""
        ...

    def aead_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """Decrypt ``ciphertext || tag``; raise on authentication failure."""
        ...

    # --- Key agreement (milestone stubs for later TLS work) ---------------

    def generate_ephemeral_keypair(self) -> KeyPair:
        ...

    def derive_shared_secret(self, sk: bytes, peer_pk: bytes) -> bytes:
        ...

    # --- Signatures (milestone stubs for later mandate work) --------------

    def generate_signing_keypair(self) -> KeyPair:
        ...

    def sign(self, sk: bytes, message: bytes) -> bytes:
        ...

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        ...
