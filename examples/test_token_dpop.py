import requests
import time
import uuid
from jwcrypto import jwk, jwt
import logging

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
