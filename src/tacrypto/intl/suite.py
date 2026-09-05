"""International crypto suite backed by the ``cryptography`` library."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tacrypto.types import KeyPair

_HASH = hashes.SHA256()
_HASH_LEN = 32
_TAG_LEN = 16


class IntlCryptoSuite:
    """SHA-256 / HMAC-SHA256 / HKDF / AES-128-GCM (+ X25519 & ECDSA stubs)."""

    @property
    def name(self) -> str:
        return "intl"

    def hash(self, data: bytes) -> bytes:
        digest = hashes.Hash(_HASH)
        digest.update(data)
        return digest.finalize()

    def hmac(self, key: bytes, data: bytes) -> bytes:
        h = hmac.HMAC(key, _HASH)
        h.update(data)
        return h.finalize()

    def hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        # RFC 5869: if salt is not provided, it is set to HashLen zeros.
        if salt == b"":
            salt = b"\x00" * _HASH_LEN
        return self.hmac(salt, ikm)

    def hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        if length <= 0:
            raise ValueError("length must be positive")
        return HKDFExpand(
            algorithm=_HASH,
            length=length,
            info=info,
        ).derive(prk)

    def aead_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 128/192/256 bits")
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def aead_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: bytes = b"",
    ) -> bytes:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 128/192/256 bits")
        if len(data) < _TAG_LEN:
            raise ValueError("AEAD ciphertext too short")
        try:
            return AESGCM(key).decrypt(nonce, data, aad)
        except InvalidTag as exc:
            raise ValueError("AEAD authentication failed") from exc

    def generate_ephemeral_keypair(self) -> KeyPair:
        sk = x25519.X25519PrivateKey.generate()
        return KeyPair(
            private_key=sk.private_bytes_raw(),
            public_key=sk.public_key().public_bytes_raw(),
        )

    def derive_shared_secret(self, sk: bytes, peer_pk: bytes) -> bytes:
        priv = x25519.X25519PrivateKey.from_private_bytes(sk)
        pub = x25519.X25519PublicKey.from_public_bytes(peer_pk)
        return priv.exchange(pub)

    def generate_signing_keypair(self) -> KeyPair:
        sk = ec.generate_private_key(ec.SECP256R1())
        pub = sk.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return KeyPair(
            private_key=sk.private_numbers().private_value.to_bytes(32, "big"),
            public_key=pub,
        )

    def sign(self, sk: bytes, message: bytes) -> bytes:
        if len(sk) != 32:
            raise ValueError("ECDSA-P256 private key must be 32 bytes")
        priv = ec.derive_private_key(int.from_bytes(sk, "big"), ec.SECP256R1())
        return priv.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
        try:
            pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
