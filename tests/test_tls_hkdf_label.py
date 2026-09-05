"""Unit tests for HKDF-Expand-Label / Derive-Secret encoding."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.tls.hkdf_label import derive_secret, hkdf_expand_label, hkdf_label


def test_hkdf_label_matches_rfc8448_derived_info():
    # RFC 8448: info for "tls13 derived" with Hash("")
    empty_hash = bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    info = hkdf_label(32, "derived", empty_hash)
    assert info == bytes.fromhex(
        "00200d746c733133206465726976656420"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hkdf_label_key_and_iv_info():
    assert hkdf_label(16, "key", b"") == bytes.fromhex("001009746c733133206b657900")
    assert hkdf_label(12, "iv", b"") == bytes.fromhex("000c08746c73313320697600")


def test_derive_secret_derived_from_early():
    suite = get_suite("intl")
    early = bytes.fromhex(
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    )
    out = derive_secret(suite, early, "derived", b"")
    assert out == bytes.fromhex(
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
    )


def test_hkdf_expand_label_finished_key():
    suite = get_suite("intl")
    base = bytes.fromhex(
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
    )
    fk = hkdf_expand_label(suite, base, "finished", b"", 32)
    assert fk == bytes.fromhex(
        "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
    )
