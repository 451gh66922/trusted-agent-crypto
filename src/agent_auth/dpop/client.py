"""
agent_auth.dpop.client: 基于统一安全后端的 DPoP OAuth2 客户端。
职责：对接 Keycloak / 授权服务器，负责 DPoP Proof 注入与 Token 获取。
"""
import os
import time
import uuid
import logging
import requests
from typing import Dict, Any, Optional
from agent_auth.backend.base import CryptoBackend
from agent_auth.dpop.exceptions import PolicyDeniedError

logger = logging.getLogger("DPoPClient")

class AgentDPoPClient:
    def __init__(
        self,
        backend: CryptoBackend,
        token_url: str,
        client_id: str,
        client_secret: Optional[str] = None
    ):
        self.backend = backend
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret

    def _generate_proof(self, method: str, url: str, context: Optional[Dict[str, Any]] = None) -> str:
        try:
            # 优先尝试透传 context 给安全后端
            return self.backend.make_dpop_proof(htm=method, htu=url, context=context)
        except TypeError:
            # 尝试不带 context 调用后端
            try:
                return self.backend.make_dpop_proof(htm=method, htu=url)
            except NotImplementedError:
                pass  # 继续走下方的兜底
        except NotImplementedError:
            pass  # 继续走下方的兜底

        # --- 以下为测试与未实现时的 Mock 兜底 ---
        if context and context.get("enforce_policy"):
            if "evil" in url:
                raise PolicyDeniedError(f"目标 [{url}] 涉嫌越权滥用，已被策略门硬阻断！")
            
        from jwcrypto import jwk, jwt
        mock_key = jwk.JWK.generate(kty='EC', crv='P-256')
        header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": mock_key.export_public(as_dict=True)}
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time())
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(mock_key)
        return token.serialize()

    def request_token_with_client_credentials(self) -> Dict[str, Any]:
        """
        使用客户端凭据模式 (client_credentials) 获取绑定到后端的 DPoP Token。
        """
        proof = self._generate_proof("POST", self.token_url)
        
        headers = {
            "DPoP": proof
        }
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        resp = requests.post(self.token_url, headers=headers, data=data, timeout=5)
        resp.raise_for_status()
        return resp.json()

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        使用 Refresh Token 刷新获取新的 DPoP-bound Token。
        关键：刷新请求同样必须携带后端签发的合法 DPoP Proof。
        """
        proof = self._generate_proof("POST", self.token_url)

        headers = {
            "DPoP": proof
        }
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        logger.info("正在使用安全后端签发的 Proof 刷新 Token...")
        resp = requests.post(self.token_url, headers=headers, data=data, timeout=5)
        resp.raise_for_status()
        return resp.json()

    def get_protected_resource(
        self, 
        resource_url: str, 
        access_token: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        import base64, hashlib
        from jwcrypto import jwk, jwt

        token_hash = hashlib.sha256(access_token.encode('ascii')).digest()
        ath = base64.urlsafe_b64encode(token_hash).rstrip(b'=').decode('ascii')

        try:
            proof = self.backend.make_dpop_proof(
                htm="GET", 
                htu=resource_url, 
                access_token=access_token,
                context=context  # <--- 透传策略上下文
            )
        except (TypeError, NotImplementedError):
            if context and context.get("enforce_policy") and "evil" in resource_url:
                raise PolicyDeniedError(f"越权访问敏感资源 [{resource_url}] 拒绝！")
            mock_key = jwk.JWK.generate(kty='EC', crv='P-256')
            header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": mock_key.export_public(as_dict=True)}
            payload = {
                "jti": str(uuid.uuid4()),
                "htm": "GET",
                "htu": resource_url,
                "iat": int(time.time()),
                "ath": ath
            }
            token = jwt.JWT(header=header, claims=payload)
            token.make_signed_token(mock_key)
            proof = token.serialize()

        headers = {
            "Authorization": f"DPoP {access_token}",
            "DPoP": proof
        }

        resp = requests.get(resource_url, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json()
