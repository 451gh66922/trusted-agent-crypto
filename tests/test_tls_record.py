"""Formal TLS record layer framing tests."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.tls.record import (
    ContentType,
    RecordError,
    RecordLayer,
    TLSPlaintext,
    parse_inner_plaintext,
    parse_plaintext,
)
from tacrypto.tls.traffic import traffic_keys
from tacrypto.tls.key_schedule import KeySchedule


def test_plaintext_roundtrip():
    rec = TLSPlaintext(ContentType.HANDSHAKE, b"\x01\x02\x03")
    raw = rec.encode()
    parsed, rest = parse_plaintext(raw)
    assert rest == b""
    assert parsed.content_type == ContentType.HANDSHAKE
    assert parsed.fragment == b"\x01\x02\x03"


def test_inner_plaintext_padding():
    content, ctype = parse_inner_plaintext(b"hello\x17\x00\x00")
    assert content == b"hello" and ctype == ContentType.APPLICATION_DATA


def test_encrypted_record_roundtrip_and_seq():
    suite = get_suite("intl")
    # Derive some traffic keys via empty-ish schedule materials
    ks = KeySchedule(suite)
    ks.derive_early_secret()
    # Fake handshake secret path with zeros shared secret for unit test keys
    shared = b"\x11" * 32
    th = suite.hash(b"hello")
    hs = ks.derive_handshake_secrets(shared, th)
    keys = traffic_keys(suite, hs.client_handshake_traffic_secret)

    writer = RecordLayer(suite)
    reader = RecordLayer(suite)
    writer.install_keys(write=keys)
    reader.install_keys(read=keys)

    wire = writer.seal(ContentType.APPLICATION_DATA, b"pay:42", padding=3)
    assert wire[0] == int(ContentType.APPLICATION_DATA)
    ctype, pt, rest = reader.open(wire)
    assert rest == b"" and ctype == ContentType.APPLICATION_DATA and pt == b"pay:42"

    wire2 = writer.seal(ContentType.HANDSHAKE, b"\x14\x00\x00\x01\x00")
    ctype2, pt2, _ = reader.open(wire2)
    assert ctype2 == ContentType.HANDSHAKE and pt2.startswith(b"\x14")


def test_tampered_record_rejected():
    suite = get_suite("intl")
    ks = KeySchedule(suite)
    ks.derive_early_secret()
    hs = ks.derive_handshake_secrets(b"\x22" * 32, suite.hash(b"x"))
    keys = traffic_keys(suite, hs.server_handshake_traffic_secret)
    w = RecordLayer(suite)
    r = RecordLayer(suite)
    w.install_keys(write=keys)
    r.install_keys(read=keys)
    wire = bytearray(w.seal(ContentType.APPLICATION_DATA, b"secret"))
    wire[-1] ^= 0x01
    try:
        r.open(bytes(wire))
        raise AssertionError("expected RecordError")
    except RecordError:
        pass
