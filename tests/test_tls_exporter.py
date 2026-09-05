"""TLS-Exporter tests (RFC 8446 §7.5)."""

from __future__ import annotations

import json
from pathlib import Path

from tacrypto import get_suite
from tacrypto.tls.exporter import tls_exporter
from tacrypto.tls.hkdf_label import derive_secret, hkdf_expand_label
from tacrypto.tls.key_schedule import KeySchedule

VECTORS = Path(__file__).parent / "vectors" / "rfc8448_simple_1rtt.json"


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


def test_exporter_deterministic_and_label_separates():
    suite = get_suite("intl")
    vec = json.loads(VECTORS.read_text(encoding="utf-8"))
    ems = _h(vec["exporter_master_secret"])

    a = tls_exporter(suite, ems, "EXPORTER-ta-demo", b"ctx-a", 32)
    b = tls_exporter(suite, ems, "EXPORTER-ta-demo", b"ctx-a", 32)
    c = tls_exporter(suite, ems, "EXPORTER-ta-demo", b"ctx-b", 32)
    d = tls_exporter(suite, ems, "other-label", b"ctx-a", 32)

    assert a == b
    assert a != c
    assert a != d
    assert len(a) == 32


def test_exporter_matches_manual_rfc_construction():
    suite = get_suite("intl")
    vec = json.loads(VECTORS.read_text(encoding="utf-8"))
    ems = _h(vec["exporter_master_secret"])
    label = "EXPORTER-Channel-Binding"
    context = b"\x00\x01\x02"
    length = 16

    # Manual: Derive-Secret(ems, label, "") then Expand-Label(..., "exporter", Hash(ctx))
    secret = derive_secret(suite, ems, label, b"")
    expected = hkdf_expand_label(suite, secret, "exporter", suite.hash(context), length)
    assert tls_exporter(suite, ems, label, context, length) == expected


def test_client_server_exporters_match_after_schedule():
    suite = get_suite("intl")
    vec = json.loads(VECTORS.read_text(encoding="utf-8"))
    ks_c = KeySchedule(suite)
    ks_s = KeySchedule(suite)
    for ks in (ks_c, ks_s):
        ks.run(
            shared_secret=_h(vec["dhe"]),
            transcript_hash_hello=_h(vec["transcript_hash_hello"]),
            transcript_hash_server_finished=_h(vec["transcript_hash_server_finished"]),
        )
    assert ks_c.exporter_master_secret == ks_s.exporter_master_secret
    exp_c = tls_exporter(
        suite, ks_c.exporter_master_secret, "ta demo", b"merchant", 32
    )
    exp_s = tls_exporter(
        suite, ks_s.exporter_master_secret, "ta demo", b"merchant", 32
    )
    assert exp_c == exp_s
