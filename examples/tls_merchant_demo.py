"""End-to-end: independent peers + framed records + bound mandate + attack rejects."""

from __future__ import annotations

import os

from tacrypto import get_suite
from tacrypto.policy import (
    MandateRequest,
    MandateService,
    MerchantVerifier,
    PolicyConfig,
    PolicyDenyReason,
    PolicyEngine,
    PolicyViolation,
)
from tacrypto.se import connect
from tacrypto.tls import (
    MemoryTransport,
    MerchantServer,
    TlsClient,
    app_exchange,
    handshake_over_transport,
)


def main() -> None:
    suite = get_suite("intl")
    se = connect("intl", max_amount=5000)
    se.select()
    identity = se.gen_identity_key()
    print(f"SE suite={se.get_suite_name()} identity_key_id={identity.key_id}")

    client = TlsClient(suite, se=se)
    merchant = MerchantServer(suite)
    c_tx, m_tx = MemoryTransport.pair()
    print("peers: TlsClient (SE-ECDHE) <-> MerchantServer via MemoryTransport")
    handshake_over_transport(client, merchant, c_tx, m_tx)
    print("handshake: CONNECTED")
    print(f"  exporter_master match: {client.exporter_master_secret == merchant.exporter_master_secret}")
    print(f"  channel_binding      : {client.channel_binding.hex()}")

    order = b'{"item":"tea","qty":2}'
    pt = app_exchange(client, merchant, c_tx, m_tx, order, padding=2)
    print(f"client->merchant app data: {pt!r}")
    ack = app_exchange(merchant, client, m_tx, c_tx, b"OK")
    print(f"merchant->client app data: {ack!r}")

    policy = PolicyEngine(
        PolicyConfig(
            max_amount=5000,
            allowed_agents=frozenset({"cashier"}),
            allowed_merchants=frozenset({"tea-shop"}),
        )
    )
    svc = MandateService(suite, se, identity, policy=policy)
    svc.install_channel_binding(client.channel_binding)
    mandate = MandateRequest(
        action="pay",
        agent_id="cashier",
        amount=100,
        merchant_id="tea-shop",
        nonce=os.urandom(8),
    )
    bound = svc.authorize_and_sign(mandate)
    verifier = MerchantVerifier(
        suite,
        expected_binding=merchant.channel_binding,
        agent_public_key=identity.public_key,
        policy=PolicyEngine(PolicyConfig(max_amount=5000)),
    )
    result = verifier.verify(bound)
    print(f"bound mandate merchant verify: {result.ok} mandate={result.mandate}")
    assert result.ok

    # --- Attack demos ---
    print("--- attack rejects ---")
    try:
        svc.authorize_and_sign(
            MandateRequest(
                action="pay", agent_id="cashier", amount=99999, merchant_id="tea-shop",
                nonce=os.urandom(8),
            )
        )
        raise SystemExit("expected over-limit reject")
    except PolicyViolation as exc:
        print(f"  over-limit: {exc.decision.reason.value} ({exc.decision.detail})")

    # Channel redirect: present channel-A mandate to channel-B merchant
    se_b = connect("intl")
    se_b.select()
    client_b = TlsClient(suite, se=se_b)
    merchant_b = MerchantServer(suite)
    cb, mb = MemoryTransport.pair()
    handshake_over_transport(client_b, merchant_b, cb, mb)
    assert merchant_b.channel_binding != merchant.channel_binding
    redirected = MerchantVerifier(
        suite,
        expected_binding=merchant_b.channel_binding,
        agent_public_key=identity.public_key,
    ).verify(bound)
    assert not redirected.ok and redirected.reason == PolicyDenyReason.BINDING_MISMATCH
    print(f"  channel-redirect: {redirected.reason} — REJECTED")

    close_wire = client.close()
    level, desc = merchant.handle_alert(close_wire)
    print(f"close_notify: {desc.name} -> merchant state CLOSED")
    print("demo complete")


if __name__ == "__main__":
    main()
