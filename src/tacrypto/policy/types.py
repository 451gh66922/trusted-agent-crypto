"""Mandate / authorization policy types."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyDenyReason(str, Enum):
    ACTION_NOT_ALLOWED = "action_not_allowed"
    AMOUNT_EXCEEDED = "amount_exceeded"
    AMOUNT_REQUIRED = "amount_required"
    AMOUNT_BELOW_MINIMUM = "amount_below_minimum"
    BINDING_REQUIRED = "binding_required"
    BINDING_MISMATCH = "binding_mismatch"
    AGENT_NOT_ALLOWED = "agent_not_allowed"
    MERCHANT_NOT_ALLOWED = "merchant_not_allowed"
    CURRENCY_NOT_ALLOWED = "currency_not_allowed"
    MANDATE_EXPIRED = "mandate_expired"
    MANDATE_NOT_YET_VALID = "mandate_not_yet_valid"
    NONCE_REPLAY = "nonce_replay"
    RATE_LIMITED = "rate_limited"
    BODY_TOO_LARGE = "body_too_large"


@dataclass(frozen=True, slots=True)
class MandateRequest:
    """Host-constructed mandate **without** channel_binding (SE fills it)."""

    action: str
    agent_id: str
    amount: int | None = None
    currency: str = "CNY"
    merchant_id: str = ""
    nonce: bytes = b""
    not_before: int | None = None  # unix seconds
    expires_at: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def canonical_body(self) -> bytes:
        """Deterministic JSON body used for hashing (no channel_binding)."""
        payload: dict[str, Any] = {
            "action": self.action,
            "agent_id": self.agent_id,
            "amount": self.amount,
            "currency": self.currency,
            "merchant_id": self.merchant_id,
            "nonce": self.nonce.hex(),
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "extra": self.extra,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class BoundMandate:
    """Mandate after SE attached channel_binding and signature."""

    body: bytes
    channel_binding: bytes
    signature: bytes
    key_id: int

    def signed_bytes(self) -> bytes:
        """Exact bytes that were hashed/signed inside SE."""
        return self.body + b"|" + self.channel_binding


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: PolicyDenyReason | None = None
    detail: str = ""

    @classmethod
    def allow(cls) -> PolicyDecision:
        return cls(allowed=True)

    @classmethod
    def deny(cls, reason: PolicyDenyReason, detail: str = "") -> PolicyDecision:
        return cls(allowed=False, reason=reason, detail=detail)


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Static authorization policy evaluated before SE signing."""

    allowed_actions: frozenset[str] = frozenset({"pay", "transfer", "query"})
    allowed_agents: frozenset[str] | None = None  # None = any
    allowed_merchants: frozenset[str] | None = None  # None = any
    allowed_currencies: frozenset[str] = frozenset({"CNY", "USD"})
    max_amount: int = 10_000
    min_amount: int = 0
    require_channel_binding: bool = True
    require_amount_for_actions: frozenset[str] = frozenset({"pay", "transfer"})
    max_body_bytes: int = 250
    # Rate limit: max N mandates per agent in a sliding window (seconds)
    rate_limit_count: int | None = None
    rate_limit_window_sec: int = 60
