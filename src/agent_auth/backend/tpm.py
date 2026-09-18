"""TpmBackend：Stub，仅用于「卸载后端 = 拔卡」对照与插拔模拟演示。

06 计划已取消真硬件路径；本文件不调用真实 TPM 驱动，
与 SoftSE 共用 CryptoBackend 接口，仅保留形态切换占位。
"""

from __future__ import annotations

from typing import Any

from agent_auth.backend.base import CryptoBackend


class TpmBackend(CryptoBackend):
    """Stub 后端；请用 SoftSEBackend 进行真实签名。"""

    def get_public_key(self) -> dict[str, Any]:
        raise NotImplementedError("TPM 硬件路径已取消，仅作插拔模拟对照；请用 SoftSEBackend")

    def make_dpop_proof(
        self,
        *,
        htm: str,
        htu: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        raise NotImplementedError("TPM 硬件路径已取消，仅作插拔模拟对照；请用 SoftSEBackend")

    def sign_if_allowed(self, *, operation: str, context: dict[str, Any]) -> bytes:
        raise NotImplementedError("TPM 硬件路径已取消，仅作插拔模拟对照；请用 SoftSEBackend")
