import os
import requests
import time
import uuid
from jwcrypto import jwk, jwt
import logging
from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()

# 从环境变量读取，两个脚本共享这个配置
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# 防御性校验（防止忘记配置环境）
if not CLIENT_SECRET:
    raise EnvironmentError("❌ 错误: 未在 .env 文件中找到 CLIENT_SECRET")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DPoPTest")

# 配置项
TOKEN_URL = "http://192.168.201.128:8080/realms/crypto-contest/protocol/openid-connect/token"
CLIENT_ID = "agent-app"
CLIENT_SECRET = "2untpDkJ0DAJeULrzPxiBO1s1HsNdUjp"

# 生成临时密钥 (模拟 SE)
key = jwk.JWK.generate(kty='EC', crv='P-256')

def get_dpop_token():
    # 构造 DPoP Proof
    payload = {
        "jti": str(uuid.uuid4()),
        "htm": "POST",
        "htu": TOKEN_URL,
        "iat": int(time.time())
    }
    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": key.export_public(as_dict=True)}
    
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)
    dpop_proof = token.serialize()

    # 发送请求
    headers = {"DPoP": dpop_proof}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "dpop_jkt": key.thumbprint()
    }

    try:
        resp = requests.post(TOKEN_URL, headers=headers, data=data, timeout=5)
        logger.info(f"Status: {resp.status_code}")
        logger.info(f"Response: {resp.json()}")
    except Exception as e:
        logger.error(f"Request failed: {e}")

if __name__ == "__main__":
    get_dpop_token()
