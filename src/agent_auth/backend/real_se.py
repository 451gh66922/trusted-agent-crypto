"""RealSEBackend：USB / 智能卡 SE（终局形态）。"""

from __future__ import annotations

from typing import Any

from agent_auth.backend.base import CryptoBackend


class RealSEBackend(CryptoBackend):
    """经 APDU 或 PKCS#11 访问真卡；插拔即授权能力随卡走。"""

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
