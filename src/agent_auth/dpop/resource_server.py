"""
极简资源服务器 (Resource Server, RS)。
负责受保护资源的暴露与 DPoP 令牌绑定的强校验。
"""
import json
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from jwcrypto import jwk, jwt

class DPoPResourceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/api/protected-resource":
            self.send_response(404)
            self.end_headers()
            return

        # 1. 提取 Authorization 头与 DPoP 头
        auth_header = self.headers.get("Authorization", "")
        dpop_header = self.headers.get("DPoP", "")

        if not auth_header.startswith("DPoP ") or not dpop_header:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "invalid_dpop_request",
                "error_description": "缺少合法 DPoP Authorization 或 DPoP Proof"
            }).encode())
            return

        access_token = auth_header.split(" ")[1]

        # 2. 校验 DPoP Proof
        try:
            # 1. 提取 Proof Header 中的公钥 (JWT 第一段 Base64)
            raw_header = dpop_header.split(".")[0]
            padded_header = raw_header + "=" * ((4 - len(raw_header) % 4) % 4)
            header_json = json.loads(base64.urlsafe_b64decode(padded_header.encode()).decode())
            proof_key = jwk.JWK(**header_json["jwk"])

            # 2. 用提取出的公钥完整校验 Proof 的签名和有效性
            proof_token = jwt.JWT(key=proof_key, jwt=dpop_header)
            claims = json.loads(proof_token.claims)

            # 3. 校验 ath (Access Token Hash): 核心防挪用机制
            token_hash = hashlib.sha256(access_token.encode('ascii')).digest()
            expected_ath = base64.urlsafe_b64encode(token_hash).rstrip(b'=').decode('ascii')

            if claims.get("ath") != expected_ath:
                raise ValueError("ath 不匹配！Token 可能被盗用或未绑定")

            # 4. 全部校验通过，放行业务数据！
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "message": "🎉 欢迎 Agent！DPoP 身份双向绑定验证通过！",
                "data": {
                    "secret_data": "CONFIDENTIAL_TASK_PAYLOAD_2026",
                    "sender_constrained": True
                }
            }).encode())

        except Exception as e:
            print(f"\n[RS 拦截拒绝] 原因: {repr(e)}\n")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "dpop_validation_failed",
                "reason": str(e)
            }).encode())

def run_server(port: int = 9999):
    server = HTTPServer(('127.0.0.1', port), DPoPResourceHandler)
    print(f"[*] 资源服务器 (RS) 已启动，监听端口: http://127.0.0.1:{port}")
    server.serve_forever()

if __name__ == "__main__":
    run_server()
