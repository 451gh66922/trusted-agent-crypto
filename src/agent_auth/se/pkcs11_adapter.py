"""PKCS#11 适配层（真卡优先路径之一）。"""

from __future__ import annotations


class PKCS11Adapter:
    """将 CryptoBackend 操作映射到 PKCS#11 会话。"""

    def __init__(self, module_path: str) -> None:
        raise NotImplementedError
