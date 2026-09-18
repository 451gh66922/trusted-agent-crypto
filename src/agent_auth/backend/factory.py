"""
统一安全后端工厂 (Backend Factory)。
支持通过环境变量 AUTH_BACKEND 或显式参数动态切换三种安全形态：
1. soft_se: SoftSE 芯片/软加密模式 (私钥受保护不可导出)
2. software: 传统软件私钥模式 (故意脆弱，用于反衬对比)
3. unplugged: 拔除/卸载模拟模式 (硬件不在场，拒绝一切签名)
"""
import os
from typing import Dict, Any, Optional
from agent_auth.backend.base import CryptoBackend
from agent_auth.backend.soft import SoftSEBackend

class UnpluggedBackend(CryptoBackend):
    """拔除模拟后端：模拟安全芯片/后端被拔下或卸载的状态"""
    def get_public_key(self) -> dict[str, Any]:
        raise RuntimeError("HARDWARE_NOT_PRESENT: 安全硬件/后端未连接或已被拔除！")

    def make_dpop_proof(self, *args, **kwargs) -> str:
        raise RuntimeError("HARDWARE_NOT_PRESENT: 无法签发 Proof，安全芯片不在场！")

    def sign_if_allowed(self, *args, **kwargs) -> bytes:
        raise RuntimeError("HARDWARE_NOT_PRESENT: 签名拒绝，设备离线！")

class SoftwareBaselineBackend(CryptoBackend):
    """传统软件模式：故意将私钥暴露给外部读取，供 R3 演示私钥窃取漏洞"""
    def __init__(self):
        from jwcrypto import jwk
        self.raw_key = jwk.JWK.generate(kty='EC', crv='P-256')

    def export_private_key_vulnerable(self) -> str:
        """故意留出的后门导出接口：展示软件实现的脆弱性"""
        return self.raw_key.export_private()

    def get_public_key(self) -> dict[str, Any]:
        import json
        return json.loads(self.raw_key.export_public())

    def make_dpop_proof(
        self, 
        *, 
        htm: str, 
        htu: str, 
        access_token: Optional[str] = None, 
        nonce: Optional[str] = None,
        context: Optional[dict[str, Any]] = None
    ) -> str:
        import time, uuid, hashlib, base64
        from jwcrypto import jwt
        from agent_auth.dpop.exceptions import PolicyDeniedError

        # 模拟 W4 策略门规则：
        # 如果传入了 context 且开启了策略检查：校验目标是否在白名单内
        if context and context.get("enforce_policy"):
            allowed_recipients = ["http://localhost:8080", "http://127.0.0.1:8081", "http://127.0.0.1:9999"]
            is_allowed = any(htu.startswith(allowed) for allowed in allowed_recipients)
            if not is_allowed:
                raise PolicyDeniedError(
                    reason=f"目标 URL [{htu}] 不在受信白名单内，任务 ID: {context.get('task_id')}",
                    reason_code="POLICY_DENIED_RECIPIENT"
                )

        header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": self.get_public_key()}
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": htm,
            "htu": htu,
            "iat": int(time.time())
        }
        if access_token:
            token_hash = hashlib.sha256(access_token.encode('ascii')).digest()
            payload["ath"] = base64.urlsafe_b64encode(token_hash).rstrip(b'=').decode('ascii')
        if nonce:
            payload["nonce"] = nonce

        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self.raw_key)
        return token.serialize()

    def sign_if_allowed(self, *, operation: str, context: dict[str, Any]) -> bytes:
        return b"mock_software_signature"

def get_crypto_backend(mode: Optional[str] = None) -> CryptoBackend:
    """
    获取当前配置的安全后端。
    优先读取入参 mode，未指定则读取环境变量 AUTH_BACKEND，默认 soft_se。
    """
    selected_mode = mode or os.getenv("AUTH_BACKEND", "soft_se").lower()

    if selected_mode == "soft_se":
        return SoftSEBackend()
    elif selected_mode == "software":
        return SoftwareBaselineBackend()
    elif selected_mode in ("unplugged", "none", "removed"):
        return UnpluggedBackend()
    else:
        raise ValueError(f"未知后端模式: {selected_mode}，可选 [soft_se, software, unplugged]")
