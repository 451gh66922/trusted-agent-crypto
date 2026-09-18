import os
import requests
import logging
from dotenv import load_dotenv

# 加载 .env 环境变量
load_dotenv()

# 从环境变量读取配置 (彻底杜绝硬编码)
CLIENT_ID = os.getenv("CLIENT_ID", "agent-app")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TOKEN_URL = os.getenv("TOKEN_URL", "http://localhost:8080/realms/crypto-contest/protocol/openid-connect/token")

# 防御性校验 (防止忘记配置环境)
if not CLIENT_SECRET:
    raise EnvironmentError("❌ 错误: 未在 .env 文件中找到 CLIENT_SECRET，请配置后重试！")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BearerTest")

def get_bearer_token():
    logger.info("=== [Bearer 基线测试] 发起传统 OAuth2 Token 请求 ===")
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    try:
        resp = requests.post(TOKEN_URL, data=data, timeout=5)
        logger.info(f"Keycloak 响应状态码: {resp.status_code}")
        if resp.status_code == 200:
            logger.info(f"🎉 成功获取 Bearer Token: {resp.json().get('token_type')}")
            logger.info(f"Access Token: {resp.json().get('access_token')[:25]}...")
        else:
            logger.error(f"❌ 获取失败: {resp.text}")
    except Exception as e:
        logger.error(f"网络请求异常: {e}")

if __name__ == "__main__":
    get_bearer_token()
