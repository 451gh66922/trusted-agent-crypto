import os
import time
import uuid
import logging
import requests
from dotenv import load_dotenv
from jwcrypto import jwk, jwt

# 加载 .env 环境变量
load_dotenv()

# 从环境变量读取配置 (彻底消除硬编码密码)
CLIENT_ID = os.getenv("CLIENT_ID", "agent-app")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TOKEN_URL = os.getenv("TOKEN_URL", "http://localhost:8080/realms/crypto-contest/protocol/openid-connect/token")

# 防御性校验 (防止忘记配置环境)
if not CLIENT_SECRET:
    raise EnvironmentError("❌ 错误: 未在 .env 文件中找到 CLIENT_SECRET，请配置后重试！")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DPoPTest")

# 生成临时 EC P-256 密钥对 (模拟客户端密钥)
key = jwk.JWK.generate(kty='EC', crv='P-256')

def get_dpop_token():
    logger.info("=== [DPoP 探针测试] 发起带 DPoP Proof 的 Token 请求 ===")
    
    # 构造标准 DPoP Proof (RFC 9449)
    payload = {
        "jti": str(uuid.uuid4()),
        "htm": "POST",
        "htu": TOKEN_URL,
        "iat": int(time.time())
    }
    header = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": key.export_public(as_dict=True)
    }

    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)
    dpop_proof = token.serialize()

    # 发送请求：携带 DPoP 头与公钥指纹 (jkt)
    headers = {"DPoP": dpop_proof}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "dpop_jkt": key.thumbprint()
    }

    try:
        resp = requests.post(TOKEN_URL, headers=headers, data=data, timeout=5)
        logger.info(f"Keycloak 响应状态码: {resp.status_code}")
        if resp.status_code == 200:
            token_data = resp.json()
            logger.info(f"🎉 成功获取 DPoP-bound Token: {token_data.get('token_type')}")
            logger.info(f"Access Token: {token_data.get('access_token')[:25]}...")
        else:
            logger.error(f"❌ 获取失败: {resp.text}")
    except Exception as e:
        logger.error(f"网络请求异常: {e}")

if __name__ == "__main__":
    get_dpop_token()
