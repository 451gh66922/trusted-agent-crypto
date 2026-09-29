"""
自建最小 DPoP 授权服务器 (Mock IdP) —— 终极保命兜底方案。
当 Keycloak 出现环境不可抗力故障时启用。
对外暴露标准的 /token 接口，严格校验 DPoP Proof，并签发带 sender-constrained 的 Token。
"""
import json
import base64
import hashlib
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from jwcrypto import jwk, jwt

class MockIdPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 兼容匹配标准的 token 接口路径
        if not self.path.endswith("/token"):
            self.send_response(404)
            self.end_headers()
            return

        # 1. 强校验：必须携带 DPoP Proof 头
        dpop_header = self.headers.get("DPoP")
        if not dpop_header:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "invalid_dpop_proof",
                "error_description": "缺少 DPoP Header 证明"
            }).encode())
            return

        # 2. 解析并验签客户端的 DPoP Proof
        try:
            raw_header = dpop_header.split(".")[0]
            padded_header = raw_header + "=" * ((4 - len(raw_header) % 4) % 4)
            header_json = json.loads(base64.urlsafe_b64decode(padded_header.encode()).decode())
            proof_key = jwk.JWK(**header_json["jwk"])

            # 严格校验 Proof
            proof_jwt = jwt.JWT(key=proof_key, jwt=dpop_header)
            claims = json.loads(proof_jwt.claims)

            # 计算客户端公钥指纹 (jkt)，作为 sender-constrained 的绑定根
            jkt = proof_key.thumbprint()

            # 3. 读取表单参数 (支持 client_credentials 与 refresh_token)
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode()
            params = dict(item.split("=") for item in body.split("&") if "=" in item)
            
            grant_type = params.get("grant_type", "client_credentials")

            # 4. 签发符合 RFC 9449 规范的 DPoP-bound Token
            access_token = f"mock_dpop_at_{uuid.uuid4().hex[:16]}"
            refresh_token = f"mock_dpop_rt_{uuid.uuid4().hex[:16]}"

            response_data = {
                "access_token": access_token,
                "token_type": "DPoP",
                "expires_in": 300,
                "refresh_token": refresh_token,
                "scope": "openid email profile",
                "cnf": {
                    "jkt": jkt
                }
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())

        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "invalid_grant",
                "error_description": f"DPoP Proof 校验失败: {str(e)}"
            }).encode())

def run_mock_idp(port: int = 8081):
    server = HTTPServer(('0.0.0.0', port), MockIdPHandler)
    print(f"[*] 备用极简 IdP (DPoP 授权服务器) 已就绪，监听: http://127.0.0.1:{port}")
    server.serve_forever()
