"""可替换的密码学后端：SoftSE 主实现，TPM 仅 stub + 插拔模拟。"""

from agent_auth.backend.base import CryptoBackend

__all__ = ["CryptoBackend"]
