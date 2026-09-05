"""Week-1 demo: SE ECDHE + RFC Key Schedule + matching Exporters + AEAD seal."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.se import connect
from tacrypto.tls import record_open, run_simplified_handshake, seal


def main() -> None:
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    print(f"suite={se.get_suite_name()}  aid selected")

    result, exp_c, exp_s = run_simplified_handshake(
        suite,
        se=se,
        exporter_label="EXPORTER-ta-demo",
        exporter_context=b"merchant-v1",
        exporter_length=32,
    )
    print("handshake: OK")
    print(f"  shared_secret     = {result.shared_secret.hex()}")
    print(f"  exporter_master   = {result.exporter_master_secret.hex()}")
    print(f"  client exporter   = {exp_c.hex()}")
    print(f"  server exporter   = {exp_s.hex()}")
    assert exp_c == exp_s
    print("exporters: MATCH")

    plaintext = b'{"action":"pay","amount":100}'
    ct = seal(
        suite,
        result.traffic.application_client,
        plaintext,
        sequence=0,
        aad=b"app",
    )
    pt = record_open(
        suite,
        result.traffic.application_client,
        ct,
        sequence=0,
        aad=b"app",
    )
    print(f"aead roundtrip: {pt!r}")
    assert pt == plaintext
    print("demo complete")


if __name__ == "__main__":
    main()
