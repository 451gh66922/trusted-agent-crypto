"""AES-GCM KAT for IntlCryptoSuite (NIST SP 800-38D)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tacrypto import get_suite

VECTORS = Path(__file__).parent / "vectors" / "aes_gcm_nist.json"


def _hex(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


@pytest.fixture(scope="module")
def suite():
    return get_suite("intl")


@pytest.fixture(scope="module")
def aes_gcm_vectors():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    return data["aes_gcm"]


def test_aes_gcm_nist_tc2_encrypt_matches_kat(suite, aes_gcm_vectors):
    vec = aes_gcm_vectors[0]
    key = _hex(vec["key"])
    nonce = _hex(vec["nonce"])
    aad = _hex(vec["aad"])
    plaintext = _hex(vec["plaintext"])
    expected = _hex(vec["ciphertext"]) + _hex(vec["tag"])

    out = suite.aead_encrypt(key, nonce, plaintext, aad)
    assert out == expected


def test_aes_gcm_nist_tc2_decrypt_roundtrip(suite, aes_gcm_vectors):
    vec = aes_gcm_vectors[0]
    key = _hex(vec["key"])
    nonce = _hex(vec["nonce"])
    aad = _hex(vec["aad"])
    plaintext = _hex(vec["plaintext"])
    data = _hex(vec["ciphertext"]) + _hex(vec["tag"])

    assert suite.aead_decrypt(key, nonce, data, aad) == plaintext


def test_aes_gcm_bad_tag_rejected(suite, aes_gcm_vectors):
    vec = aes_gcm_vectors[0]
    key = _hex(vec["key"])
    nonce = _hex(vec["nonce"])
    aad = _hex(vec["aad"])
    data = bytearray(_hex(vec["ciphertext"]) + _hex(vec["tag"]))
    data[-1] ^= 0x01

    with pytest.raises(ValueError, match="authentication failed"):
        suite.aead_decrypt(key, nonce, bytes(data), aad)


def test_hash_sha256_empty(suite):
    # SHA-256("") from NIST / FIPS examples
    assert suite.hash(b"") == bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hkdf_extract_expand_smoke(suite):
    prk = suite.hkdf_extract(salt=b"\x00" * 32, ikm=b"ikm-demo")
    out = suite.hkdf_expand(prk, info=b"info", length=42)
    assert len(prk) == 32
    assert len(out) == 42
