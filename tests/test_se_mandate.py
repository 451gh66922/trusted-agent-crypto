"""Vertical slice: Host mandate → APDU SIGN → SE signs; sk never leaves SE."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.se import SeError, connect


def test_mandate_sign_intl_vertical_slice():
    suite = get_suite("intl")
    se = connect("intl")

    fci = se.select()
    assert fci.startswith(b"FCI:")
    assert se.get_suite_name() == "intl"

    identity = se.gen_identity_key()
    assert identity.key_id == 1
    assert len(identity.public_key) >= 65  # uncompressed P-256

    mandate = b'{"agent":"cashier","action":"pay","limit":100}'
    digest = suite.hash(mandate)
    signature = se.sign_mandate(identity.key_id, digest)

    assert suite.verify(identity.public_key, digest, signature)

    # Boundary check: no APDU response may contain the on-card private key.
    sk = se._applet.keys.get(identity.key_id).private_key  # noqa: SLF001
    assert sk
    for _cmd, rsp in se.transcript:
        assert sk not in rsp
        # Also ensure raw sk never appears in command data from Host API
        assert sk not in _cmd


def test_sign_before_select_fails():
    se = connect("intl")
    try:
        se.sign_mandate(1, b"\x00" * 32)
        raise AssertionError("expected SeError")
    except SeError as exc:
        assert exc.sw == 0x6982


def test_wrong_aid():
    se = connect("intl")
    try:
        se.select(b"WRONG!")
        raise AssertionError("expected SeError")
    except SeError as exc:
        assert exc.sw == 0x6A82


def test_ecdh_returns_handle_only():
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    local = se.gen_ephemeral_key()
    peer = suite.generate_ephemeral_keypair()
    handle = se.ecdh(local.key_id, peer.public_key)
    assert handle == 1
    # Shared secret kept inside applet, not in last response data beyond handle
    _cmd, rsp = se.transcript[-1]
    assert rsp[:-2] == bytes((handle,))  # data == handle only
