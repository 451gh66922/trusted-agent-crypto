"""Soft Secure Element：密钥对生成后永不提供 export_private。"""

from __future__ import annotations


class SoftSecureElement:
    """最小 SoftSE：GET_PUB / MAKE_DPOP_PROOF / SIGN_IF_ALLOWED。"""

    def __init__(self) -> None:
        raise NotImplementedError("待实现：生成不可导出密钥对")
