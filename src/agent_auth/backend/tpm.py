"""TpmBackend：Windows TPM 路径（上手体感与对照）。"""

from __future__ import annotations

from typing import Any

from agent_auth.backend.base import CryptoBackend


class TpmBackend(CryptoBackend):
    """TPM 保护 DPoP 私钥；接不通时可先用 SoftSE。"""

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
