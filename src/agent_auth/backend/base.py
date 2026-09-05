"""统一 CryptoBackend 抽象。

Agent / OAuth 客户端只依赖本接口，不绑定某一硬件实现。
禁止提供 export_private_key。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CryptoBackend(ABC):
    """SE 风格后端：密钥不出界，按策略签发证明。"""

    @abstractmethod
    def get_public_key(self) -> dict[str, Any]:
        """返回可用于 DPoP / JWK 的公钥材料。"""

    @abstractmethod
    def make_dpop_proof(
        self,
        *,
        htm: str,
        htu: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        """在芯片 / SoftSE 内构造 DPoP proof（JWT）。"""

    @abstractmethod
    def sign_if_allowed(self, *, operation: str, context: dict[str, Any]) -> bytes:
        """策略门通过后才签名；越权则拒绝。"""
