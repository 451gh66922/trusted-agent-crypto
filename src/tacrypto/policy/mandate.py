"""High-level: policy check → SE channel-bound mandate signature → merchant verify."""

from __future__ import annotations

import json
from dataclasses import dataclass

from tacrypto.base import CryptoSuite
from tacrypto.policy.engine import PolicyEngine, PolicyViolation
from tacrypto.policy.types import (
    BoundMandate,
    MandateRequest,
    PolicyConfig,
    PolicyDecision,
    PolicyDenyReason,
)
from tacrypto.se.client import PublicKeyRef, SeClient


class MandateService:
    """Orchestrates Host policy + SE-bound signing.

    Flow:
      1. PolicyEngine evaluates the mandate (amount/action/…)
      2. SE must already hold channel_binding (from TLS exporter)
      3. SE signs body||binding — Host cannot override binding
      4. Merchant verifies with public key + expected binding
    """

    def __init__(
        self,
        suite: CryptoSuite,
        se: SeClient,
        identity: PublicKeyRef,
        policy: PolicyEngine | None = None,
    ) -> None:
        self.suite = suite
        self.se = se
        self.identity = identity
        self.policy = policy or PolicyEngine(PolicyConfig())

    def install_channel_binding(self, binding: bytes) -> None:
        self.se.set_channel_binding(binding)

    def authorize_and_sign(
        self,
        mandate: MandateRequest,
        *,
        now: int | None = None,
    ) -> BoundMandate:
        expected = None
        try:
            expected = self.se.get_channel_binding()
        except Exception:
            expected = None
        self.policy.authorize_or_raise(
            mandate,
            expected_binding=expected,
            provided_binding=expected,
            now=now,
        )
        body = mandate.canonical_body()
        binding, signature = self.se.sign_bound_mandate(self.identity.key_id, body)
        self.policy.remember_authorization(mandate, now=now)
        return BoundMandate(
            body=body,
            channel_binding=binding,
            signature=signature,
            key_id=self.identity.key_id,
        )

    def verify_bound(
        self,
        bound: BoundMandate,
        *,
        public_key: bytes | None = None,
        expected_binding: bytes | None = None,
    ) -> bool:
        pk = public_key if public_key is not None else self.identity.public_key
        if expected_binding is not None and bound.channel_binding != expected_binding:
            return False
        digest = self.suite.hash(bound.signed_bytes())
        return self.suite.verify(pk, digest, bound.signature)


@dataclass(frozen=True, slots=True)
class MerchantVerifyResult:
    ok: bool
    reason: PolicyDenyReason | str | None = None
    detail: str = ""
    mandate: dict | None = None


class MerchantVerifier:
    """Merchant-side checks: binding match + signature + optional local policy."""

    def __init__(
        self,
        suite: CryptoSuite,
        *,
        expected_binding: bytes,
        agent_public_key: bytes,
        policy: PolicyEngine | None = None,
    ) -> None:
        self.suite = suite
        self.expected_binding = expected_binding
        self.agent_public_key = agent_public_key
        self.policy = policy

    def verify(self, bound: BoundMandate) -> MerchantVerifyResult:
        if bound.channel_binding != self.expected_binding:
            return MerchantVerifyResult(
                ok=False,
                reason=PolicyDenyReason.BINDING_MISMATCH,
                detail="mandate binding != merchant TLS exporter binding",
            )
        digest = self.suite.hash(bound.signed_bytes())
        if not self.suite.verify(self.agent_public_key, digest, bound.signature):
            return MerchantVerifyResult(
                ok=False,
                reason="bad_signature",
                detail="signature verification failed",
            )
        try:
            obj = json.loads(bound.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return MerchantVerifyResult(ok=False, reason="bad_body", detail=str(exc))

        if self.policy is not None:
            # Reconstruct a MandateRequest for local re-check (defense in depth)
            try:
                req = MandateRequest(
                    action=obj["action"],
                    agent_id=obj["agent_id"],
                    amount=obj.get("amount"),
                    currency=obj.get("currency", "CNY"),
                    merchant_id=obj.get("merchant_id") or "",
                    nonce=bytes.fromhex(obj.get("nonce") or ""),
                    not_before=obj.get("not_before"),
                    expires_at=obj.get("expires_at"),
                    extra=obj.get("extra") or {},
                )
            except (KeyError, ValueError) as exc:
                return MerchantVerifyResult(ok=False, reason="bad_body", detail=str(exc))
            decision: PolicyDecision = self.policy.evaluate(
                req,
                expected_binding=self.expected_binding,
                provided_binding=bound.channel_binding,
            )
            if not decision.allowed:
                return MerchantVerifyResult(
                    ok=False,
                    reason=decision.reason,
                    detail=decision.detail,
                    mandate=obj,
                )
            self.policy.remember_authorization(req)

        return MerchantVerifyResult(ok=True, mandate=obj)
