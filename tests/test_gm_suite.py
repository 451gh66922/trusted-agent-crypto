"""GM suite smoke tests (requires ``uv sync --extra gm``)."""

from __future__ import annotations

import importlib.util

import pytest

from tacrypto import get_suite
from tacrypto.se import connect

gmssl_available = importlib.util.find_spec("gmssl") is not None
pytestmark = pytest.mark.skipif(not gmssl_available, reason="gmssl not installed")


def test_gm_sm3_abc():
    suite = get_suite("gm")
    assert suite.hash(b"abc") == bytes.fromhex(
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    )


def test_gm_sign_verify_roundtrip():
    suite = get_suite("gm")
    pair = suite.generate_signing_keypair()
    msg = b"mandate-demo"
    sig = suite.sign(pair.private_key, msg)
    assert suite.verify(pair.public_key, msg, sig)
    assert not suite.verify(pair.public_key, msg + b"x", sig)


def test_gm_ecdh_match():
    suite = get_suite("gm")
    a = suite.generate_ephemeral_keypair()
    b = suite.generate_ephemeral_keypair()
    s1 = suite.derive_shared_secret(a.private_key, b.public_key)
    s2 = suite.derive_shared_secret(b.private_key, a.public_key)
    assert s1 == s2 and len(s1) == 32


def test_gm_aead_deferred():
    suite = get_suite("gm")
    with pytest.raises(NotImplementedError, match="SM4-GCM"):
        suite.aead_encrypt(b"\x00" * 16, b"\x00" * 12, b"pt")


def test_mandate_sign_gm_vertical_slice():
    suite = get_suite("gm")
    se = connect("gm")
    se.select()
    assert se.get_suite_name() == "gm"
    identity = se.gen_identity_key()
    digest = suite.hash(b'{"action":"transfer"}')
    sig = se.sign_mandate(identity.key_id, digest)
    assert suite.verify(identity.public_key, digest, sig)
    sk = se._applet.keys.get(identity.key_id).private_key  # noqa: SLF001
    for _cmd, rsp in se.transcript:
        assert sk not in rsp
