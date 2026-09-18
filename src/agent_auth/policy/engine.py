"""策略求值（与 se.policy_gate 配合）。"""

from __future__ import annotations

from agent_auth.policy.types import PolicyConfig


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
