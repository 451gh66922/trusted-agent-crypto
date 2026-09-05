"""Host-side policy engine for mandate authorization."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from tacrypto.policy.types import (
    MandateRequest,
    PolicyConfig,
    PolicyDecision,
    PolicyDenyReason,
)


class PolicyEngine:
    """Evaluate mandates against a static policy before asking the SE to sign.

    Channel binding *presence/match* is also checked here when the caller
    already knows the expected exporter value; the SE additionally embeds the
    binding it was given so Host cannot silently swap it at sign time.
    """

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self._seen_nonces: set[bytes] = set()
        self._agent_timestamps: dict[str, deque[int]] = defaultdict(deque)

    def evaluate(
        self,
        mandate: MandateRequest,
        *,
        expected_binding: bytes | None = None,
        provided_binding: bytes | None = None,
        now: int | None = None,
    ) -> PolicyDecision:
        cfg = self.config
        ts = int(time.time()) if now is None else now
        body = mandate.canonical_body()
        if len(body) > cfg.max_body_bytes:
            return PolicyDecision.deny(
                PolicyDenyReason.BODY_TOO_LARGE,
                f"body {len(body)} > max {cfg.max_body_bytes}",
            )
        if mandate.action not in cfg.allowed_actions:
            return PolicyDecision.deny(
                PolicyDenyReason.ACTION_NOT_ALLOWED,
                f"action {mandate.action!r} not in allowlist",
            )
        if cfg.allowed_agents is not None and mandate.agent_id not in cfg.allowed_agents:
            return PolicyDecision.deny(
                PolicyDenyReason.AGENT_NOT_ALLOWED,
                f"agent {mandate.agent_id!r} not allowed",
            )
        if (
            cfg.allowed_merchants is not None
            and mandate.merchant_id
            and mandate.merchant_id not in cfg.allowed_merchants
        ):
            return PolicyDecision.deny(
                PolicyDenyReason.MERCHANT_NOT_ALLOWED,
                f"merchant {mandate.merchant_id!r} not allowed",
            )
        if mandate.currency not in cfg.allowed_currencies:
            return PolicyDecision.deny(
                PolicyDenyReason.CURRENCY_NOT_ALLOWED,
                f"currency {mandate.currency!r} not allowed",
            )
        if mandate.action in cfg.require_amount_for_actions and mandate.amount is None:
            return PolicyDecision.deny(
                PolicyDenyReason.AMOUNT_REQUIRED,
                f"action {mandate.action!r} requires amount",
            )
        if mandate.amount is not None:
            if mandate.amount < cfg.min_amount:
                return PolicyDecision.deny(
                    PolicyDenyReason.AMOUNT_BELOW_MINIMUM,
                    f"amount {mandate.amount} < min {cfg.min_amount}",
                )
            if mandate.amount > cfg.max_amount:
                return PolicyDecision.deny(
                    PolicyDenyReason.AMOUNT_EXCEEDED,
                    f"amount {mandate.amount} > max {cfg.max_amount}",
                )
        if mandate.not_before is not None and ts < mandate.not_before:
            return PolicyDecision.deny(
                PolicyDenyReason.MANDATE_NOT_YET_VALID,
                f"not valid before {mandate.not_before}",
            )
        if mandate.expires_at is not None and ts > mandate.expires_at:
            return PolicyDecision.deny(
                PolicyDenyReason.MANDATE_EXPIRED,
                f"expired at {mandate.expires_at}",
            )
        if mandate.nonce and mandate.nonce in self._seen_nonces:
            return PolicyDecision.deny(
                PolicyDenyReason.NONCE_REPLAY, "nonce already used"
            )
        if cfg.rate_limit_count is not None:
            q = self._agent_timestamps[mandate.agent_id]
            cutoff = ts - cfg.rate_limit_window_sec
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= cfg.rate_limit_count:
                return PolicyDecision.deny(
                    PolicyDenyReason.RATE_LIMITED,
                    f"agent {mandate.agent_id!r} exceeded "
                    f"{cfg.rate_limit_count}/{cfg.rate_limit_window_sec}s",
                )
        if cfg.require_channel_binding:
            if expected_binding is None and provided_binding is None:
                return PolicyDecision.deny(
                    PolicyDenyReason.BINDING_REQUIRED,
                    "channel binding required",
                )
            if (
                expected_binding is not None
                and provided_binding is not None
                and expected_binding != provided_binding
            ):
                return PolicyDecision.deny(
                    PolicyDenyReason.BINDING_MISMATCH,
                    "channel binding does not match TLS exporter",
                )
        return PolicyDecision.allow()

    def remember_nonce(self, nonce: bytes) -> None:
        if nonce:
            self._seen_nonces.add(nonce)

    def remember_authorization(self, mandate: MandateRequest, *, now: int | None = None) -> None:
        """Record a successful authorization for rate limiting + nonce."""
        self.remember_nonce(mandate.nonce)
        if self.config.rate_limit_count is not None:
            ts = int(time.time()) if now is None else now
            self._agent_timestamps[mandate.agent_id].append(ts)

    def authorize_or_raise(
        self,
        mandate: MandateRequest,
        *,
        expected_binding: bytes | None = None,
        provided_binding: bytes | None = None,
        now: int | None = None,
    ) -> None:
        decision = self.evaluate(
            mandate,
            expected_binding=expected_binding,
            provided_binding=provided_binding,
            now=now,
        )
        if not decision.allowed:
            raise PolicyViolation(decision)


class PolicyViolation(Exception):
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        msg = decision.reason.value if decision.reason else "denied"
        if decision.detail:
            msg = f"{msg}: {decision.detail}"
        super().__init__(msg)
