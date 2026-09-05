"""DPoP proof 组装与校验辅助。"""

from __future__ import annotations

from agent_auth.backend.base import CryptoBackend


def create_dpop_proof(
    backend: CryptoBackend,
    *,
    htm: str,
    htu: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """通过后端在 SE 内签发 DPoP proof。"""
    return backend.make_dpop_proof(
        htm=htm,
        htu=htu,
        access_token=access_token,
        nonce=nonce,
    )
