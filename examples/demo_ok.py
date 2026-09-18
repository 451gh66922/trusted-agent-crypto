"""
终极全链路演示：SoftSE -> Keycloak (AS) -> 资源服务器 (RS)
R2 W2 完整验收交付物。
"""
import os
import time
import logging
import threading
from dotenv import load_dotenv
from agent_auth.backend.soft import SoftSEBackend
from agent_auth.dpop.client import AgentDPoPClient
from agent_auth.dpop.resource_server import run_server

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DemoOK")

CLIENT_ID = os.getenv("CLIENT_ID", "agent-app")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "2untpDkJ0DAJeULrzPxiB01s1HsNdUjp")
TOKEN_URL = os.getenv("TOKEN_URL", "http://localhost:8080/realms/crypto-contest/protocol/openid-connect/token")
RS_URL = "http://127.0.0.1:9999/api/protected-resource"

def main() -> None:
    logger.info("=== [Demo OK] 启动 DPoP 端到端完整授权链路 ===")

    # 1. 后台自动拉起资源服务器 (RS)
    rs_thread = threading.Thread(target=run_server, args=(9999,), daemon=True)
    rs_thread.start()
    time.sleep(0.5)

    # 2. 挂载安全后端与客户端
    backend = SoftSEBackend()
    client = AgentDPoPClient(backend, TOKEN_URL, CLIENT_ID, CLIENT_SECRET)

    try:
        # 3. 换发 Token
        token_data = client.request_token_with_client_credentials()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        logger.info("🎉 步骤 1：成功向 Keycloak 获取初始 DPoP Token！")

        # 4. 刷新 Token
        new_token_data = client.refresh_token(refresh_token)
        final_token = new_token_data.get("access_token")
        logger.info("🎉 步骤 2：成功刷新获取最新 DPoP Token！")

        # 5. 访问受保护的资源服务器 (RS)
        logger.info(f"--- 步骤 3：携带 Token 与 Proof 请求受保护业务数据: {RS_URL} ---")
        rs_data = client.get_protected_resource(RS_URL, final_token)
        
        logger.info("🏆 步骤 3 成功！资源服务器放行，业务响应:")
        logger.info(f">> {rs_data['message']}")
        logger.info(f">> 拿到核心机密数据: {rs_data['data']['secret_data']}")
        logger.info("=== 恭喜！端到端全链路 (Client -> AS -> RS) 100% 验收通关！ ===")

    except Exception as e:
        logger.error(f"❌ 流程中断: {e}")

if __name__ == "__main__":
    main()
