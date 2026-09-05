"""SoftSEBackend：软件模拟安全元件，日常开发默认后端。"""

from __future__ import annotations

from typing import Any

from agent_auth.backend.base import CryptoBackend


class SoftSEBackend(CryptoBackend):
    """委托 Soft Secure Element；实现待补。"""

    def get_public_key(self) -> dict[str, Any]:
        raise NotImplementedError

    def make_dpop_proof(
        self,
        *,
        htm: str,
        htu: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        raise NotImplementedError

    def sign_if_allowed(self, *, operation: str, context: dict[str, Any]) -> bytes:
        raise NotImplementedError
