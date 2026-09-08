import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BearerTest")

CLIENT_SECRET = "2untpDkJ0DAJeULrzPxiBO1s1HsNdUjp"
TOKEN_URL = "http://192.168.201.128:8080/realms/crypto-contest/protocol/openid-connect/token"

def get_bearer_token():
    data = {"grant_type": "client_credentials", "client_id": "agent-app", "client_secret": CLIENT_SECRET}
    try:
        resp = requests.post(TOKEN_URL, data=data, timeout=5)
        logger.info(f"Status: {resp.status_code}")
        logger.info(f"Response: {resp.json()}")
    except Exception as e:
        logger.error(f"Failed: {e}")

if __name__ == "__main__":
    get_bearer_token()
