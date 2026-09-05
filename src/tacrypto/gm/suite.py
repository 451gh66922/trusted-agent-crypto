"""GM crypto suite backed by the pure-Python ``gmssl`` package.

AEAD (SM4-GCM) is deferred — not required for the SE mandate vertical slice.
Ephemeral agreement uses SM2 curve ECDH (x-coordinate of shared point).
"""

from __future__ import annotations

from gmssl import func, sm2, sm3

from tacrypto.types import KeyPair

_HASH_LEN = 32


def _sm3(data: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))


def _hmac_sm3(key: bytes, data: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = _sm3(key)
    key = key.ljust(block, b"\x00")
    o_key = bytes(b ^ 0x5C for b in key)
    i_key = bytes(b ^ 0x36 for b in key)
    return _sm3(o_key + _sm3(i_key + data))


def _gen_sm2_keypair() -> KeyPair:
    sk_hex = func.random_hex(64)
    helper = sm2.CryptSM2(private_key=sk_hex, public_key="")
    pk_hex = helper._kg(int(sk_hex, 16), helper.ecc_table["g"])
    # Store uncompressed point with 0x04 prefix for a stable byte encoding.
    return KeyPair(
        private_key=bytes.fromhex(sk_hex),
        public_key=b"\x04" + bytes.fromhex(pk_hex),
    )


def _crypt(sk: bytes | None, pk: bytes | None) -> sm2.CryptSM2:
    sk_hex = sk.hex() if sk is not None else ""
    pk_hex = ""
    if pk is not None:
        pk_hex = pk[1:].hex() if pk.startswith(b"\x04") else pk.hex()
    return sm2.CryptSM2(private_key=sk_hex, public_key=pk_hex)


class GmCryptoSuite:
    """SM3 / HMAC-SM3 / HKDF-SM3 / SM2 (+ SM2-ECDH). SM4-GCM: not yet."""

    @property
    def name(self) -> str:
        return "gm"

    def hash(self, data: bytes) -> bytes:
        return _sm3(data)

    def hmac(self, key: bytes, data: bytes) -> bytes:
        return _hmac_sm3(key, data)

    def hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        if salt == b"":
            salt = b"\x00" * _HASH_LEN
        return self.hmac(salt, ikm)

    def hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        if length <= 0:
            raise ValueError("length must be positive")
        # RFC 5869 with HMAC-SM3
        n = (length + _HASH_LEN - 1) // _HASH_LEN
        if n > 255:
            raise ValueError("length too large for HKDF-Expand")
        okm = b""
        t = b""
        for i in range(1, n + 1):
            t = self.hmac(prk, t + info + bytes((i,)))
            okm += t
        return okm[:length]

    def aead_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        raise NotImplementedError(
            "SM4-GCM is deferred; SE mandate path does not need AEAD yet"
        )

    def aead_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: bytes = b"",
    ) -> bytes:
        raise NotImplementedError(
            "SM4-GCM is deferred; SE mandate path does not need AEAD yet"
        )

    def generate_ephemeral_keypair(self) -> KeyPair:
        return _gen_sm2_keypair()

    def derive_shared_secret(self, sk: bytes, peer_pk: bytes) -> bytes:
        if len(sk) != 32:
            raise ValueError("SM2 private key must be 32 bytes")
        pk_hex = peer_pk[1:].hex() if peer_pk.startswith(b"\x04") else peer_pk.hex()
        helper = sm2.CryptSM2(private_key=sk.hex(), public_key="")
        point = helper._kg(int(sk.hex(), 16), pk_hex)
        # Shared secret = x-coordinate (first 32 bytes of the affine point)
        return bytes.fromhex(point[:64])

    def generate_signing_keypair(self) -> KeyPair:
        return _gen_sm2_keypair()

    def sign(self, sk: bytes, message: bytes) -> bytes:
        if len(sk) != 32:
            raise ValueError("SM2 private key must be 32 bytes")
        # Need matching public key for Z value in SM2
        helper = sm2.CryptSM2(private_key=sk.hex(), public_key="")
        pk_hex = helper._kg(int(sk.hex(), 16), helper.ecc_table["g"])
        crypt = sm2.CryptSM2(private_key=sk.hex(), public_key=pk_hex)
        sig_hex = crypt.sign_with_sm3(message)
        return bytes.fromhex(sig_hex)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        crypt = _crypt(None, pk)
        try:
            return bool(crypt.verify_with_sm3(signature.hex(), message))
        except Exception:
            return False
