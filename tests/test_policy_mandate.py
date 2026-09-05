"""Policy engine + SE channel-bound mandate signing (extended)."""

from __future__ import annotations

import os
import time

import pytest

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
from tacrypto.se import SeError, connect
from tacrypto.tls import MerchantServer, TlsClient, complete_handshake


def test_policy_denies_over_limit():
    engine = PolicyEngine(PolicyConfig(max_amount=100))
    m = MandateRequest(action="pay", agent_id="a1", amount=500, nonce=os.urandom(8))
    d = engine.evaluate(m, expected_binding=b"\x00" * 32, provided_binding=b"\x00" * 32)
    assert not d.allowed and d.reason == PolicyDenyReason.AMOUNT_EXCEEDED


def test_policy_denies_unknown_action():
    engine = PolicyEngine()
    m = MandateRequest(action="hack", agent_id="a1", amount=1, nonce=os.urandom(8))
    d = engine.evaluate(m, expected_binding=b"\x00" * 32, provided_binding=b"\x00" * 32)
    assert d.reason == PolicyDenyReason.ACTION_NOT_ALLOWED


def test_policy_nonce_replay():
    engine = PolicyEngine()
    nonce = os.urandom(8)
    m = MandateRequest(action="pay", agent_id="a1", amount=1, nonce=nonce)
    binding = b"\x11" * 32
    assert engine.evaluate(m, expected_binding=binding, provided_binding=binding).allowed
    engine.remember_nonce(nonce)
    d = engine.evaluate(m, expected_binding=binding, provided_binding=binding)
    assert d.reason == PolicyDenyReason.NONCE_REPLAY


def test_policy_merchant_and_rate_limit():
    engine = PolicyEngine(
        PolicyConfig(
            allowed_merchants=frozenset({"shop-a"}),
            rate_limit_count=1,
            rate_limit_window_sec=60,
        )
    )
    binding = b"\x22" * 32
    bad = MandateRequest(
        action="pay", agent_id="a", amount=1, merchant_id="shop-b", nonce=os.urandom(4)
    )
    assert (
        engine.evaluate(bad, expected_binding=binding, provided_binding=binding).reason
        == PolicyDenyReason.MERCHANT_NOT_ALLOWED
    )
    good = MandateRequest(
        action="pay", agent_id="a", amount=1, merchant_id="shop-a", nonce=os.urandom(4)
    )
    assert engine.evaluate(good, expected_binding=binding, provided_binding=binding).allowed
    engine.remember_authorization(good, now=1_700_000_000)
    again = MandateRequest(
        action="pay", agent_id="a", amount=2, merchant_id="shop-a", nonce=os.urandom(4)
    )
    d = engine.evaluate(
        again, expected_binding=binding, provided_binding=binding, now=1_700_000_001
    )
    assert d.reason == PolicyDenyReason.RATE_LIMITED


def test_policy_time_window():
    engine = PolicyEngine()
    binding = b"\x33" * 32
    now = int(time.time())
    early = MandateRequest(
        action="pay",
        agent_id="a",
        amount=1,
        nonce=os.urandom(4),
        not_before=now + 3600,
    )
    assert (
        engine.evaluate(
            early, expected_binding=binding, provided_binding=binding, now=now
        ).reason
        == PolicyDenyReason.MANDATE_NOT_YET_VALID
    )
    expired = MandateRequest(
        action="pay",
        agent_id="a",
        amount=1,
        nonce=os.urandom(4),
        expires_at=now - 10,
    )
    assert (
        engine.evaluate(
            expired, expected_binding=binding, provided_binding=binding, now=now
        ).reason
        == PolicyDenyReason.MANDATE_EXPIRED
    )


def test_end_to_end_tls_then_bound_mandate():
    suite = get_suite("intl")
    se = connect("intl", max_amount=1000)
    se.select()
    identity = se.gen_identity_key()

    client = TlsClient(suite, se=se)
    server = MerchantServer(suite)
    complete_handshake(client, server)

    svc = MandateService(suite, se, identity)
    svc.install_channel_binding(client.channel_binding)

    mandate = MandateRequest(
        action="pay",
        agent_id="cashier",
        amount=100,
        merchant_id="tea-shop",
        nonce=os.urandom(8),
    )
    bound = svc.authorize_and_sign(mandate)
    assert bound.channel_binding == client.channel_binding == server.channel_binding
    assert svc.verify_bound(bound, expected_binding=server.channel_binding)

    verifier = MerchantVerifier(
        suite,
        expected_binding=server.channel_binding,
        agent_public_key=identity.public_key,
    )
    result = verifier.verify(bound)
    assert result.ok and result.mandate["amount"] == 100

    # Tampered expected binding fails verify
    assert not svc.verify_bound(bound, expected_binding=b"\xff" * 32)


def test_channel_redirect_attack_rejected():
    """G2-style: mandate signed on channel A presented on channel B."""
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    identity = se.gen_identity_key()

    # Channel A
    client_a = TlsClient(suite, se=se)
    merchant_a = MerchantServer(suite)
    complete_handshake(client_a, merchant_a)

    svc = MandateService(suite, se, identity)
    svc.install_channel_binding(client_a.channel_binding)
    bound = svc.authorize_and_sign(
        MandateRequest(action="pay", agent_id="cashier", amount=50, nonce=os.urandom(8))
    )

    # Channel B (different handshake → different binding)
    se2 = connect("intl")
    se2.select()
    client_b = TlsClient(suite, se=se2)
    merchant_b = MerchantServer(suite)
    complete_handshake(client_b, merchant_b)
    assert client_b.channel_binding != client_a.channel_binding

    verifier_b = MerchantVerifier(
        suite,
        expected_binding=merchant_b.channel_binding,
        agent_public_key=identity.public_key,
    )
    result = verifier_b.verify(bound)
    assert not result.ok
    assert result.reason == PolicyDenyReason.BINDING_MISMATCH


def test_se_rejects_over_limit_even_if_host_skips_policy():
    suite = get_suite("intl")
    se = connect("intl", max_amount=50)
    se.select()
    identity = se.gen_identity_key()
    se.set_channel_binding(b"\xab" * 32)
    mandate = MandateRequest(
        action="pay", agent_id="a", amount=999, nonce=os.urandom(4)
    )
    with pytest.raises(SeError):
        se.sign_bound_mandate(identity.key_id, mandate.canonical_body())


def test_sign_bound_requires_binding():
    se = connect("intl")
    se.select()
    identity = se.gen_identity_key()
    mandate = MandateRequest(action="query", agent_id="a", nonce=os.urandom(4))
    with pytest.raises(SeError) as ei:
        se.sign_bound_mandate(identity.key_id, mandate.canonical_body())
    assert ei.value.sw == 0x6982


def test_host_policy_blocks_before_se():
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    identity = se.gen_identity_key()
    se.set_channel_binding(b"\x01" * 32)
    svc = MandateService(
        suite, se, identity, policy=PolicyEngine(PolicyConfig(max_amount=10))
    )
    mandate = MandateRequest(
        action="pay", agent_id="a", amount=11, nonce=os.urandom(4)
    )
    with pytest.raises(PolicyViolation):
        svc.authorize_and_sign(mandate)
