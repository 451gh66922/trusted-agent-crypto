"""
终极全链路演示：SoftSE -> Keycloak (AS) -> 资源服务器 (RS)
R2 W2~W3 核心交付物：支持三种安全后端形态切换 (soft_se / software / unplugged)。
"""
import os
import sys
import time
import logging
import argparse
import threading
from dotenv import load_dotenv

# 引用统一安全后端工厂与 DPoP 客户端组件
from agent_auth.backend.factory import get_crypto_backend
from agent_auth.dpop.client import AgentDPoPClient
from agent_auth.dpop.resource_server import run_server
from agent_auth.dpop.mock_idp import run_mock_idp

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DemoOK")

CLIENT_ID = os.getenv("CLIENT_ID", "agent-app")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TOKEN_URL = os.getenv("TOKEN_URL", "http://localhost:8080/realms/crypto-contest/protocol/openid-connect/token")
RS_URL = "http://127.0.0.1:9999/api/protected-resource"

def main() -> None:
    # 1. 严格解析 CLI 命令行参数
    parser = argparse.ArgumentParser(description="DPoP 客户端主链路演示")
    parser.add_argument(
        "--backend", 
        choices=["soft_se", "software", "unplugged"], 
        default=None,
        help="指定安全后端: soft_se (默认), software (软件私钥), unplugged (拔卡模拟)"
    )
    args, _ = parser.parse_known_args()

    # 决策优先级：命令行参数 --backend > 环境变量 AUTH_BACKEND > 默认值 soft_se
    backend_mode = args.backend or os.getenv("AUTH_BACKEND") or "soft_se"

    if not CLIENT_SECRET and ":8081" not in TOKEN_URL:
        logger.error("❌ 启动失败: 未检测到 CLIENT_SECRET！")
        logger.error("👉 请确保项目根目录存在 .env 文件，并配置了 CLIENT_SECRET=<你的客户端密钥>")
        sys.exit(1)

    logger.info("=== [Demo OK] 启动 DPoP 端到端完整授权链路 ===")
    logger.info(f"当前生效的安全后端模式: [{backend_mode}]")

    # 2. 后台按需拉起服务 (RS 与 Mock IdP)
    rs_thread = threading.Thread(target=run_server, args=(9999,), daemon=True)
    rs_thread.start()

    if ":8081" in TOKEN_URL:
        idp_thread = threading.Thread(target=run_mock_idp, args=(8081,), daemon=True)
        idp_thread.start()

    time.sleep(0.5)

    # 3. 动态获取对应的安全后端
    backend = get_crypto_backend(backend_mode)
    client = AgentDPoPClient(backend, TOKEN_URL, CLIENT_ID, CLIENT_SECRET)

    try:
        # 4. 换发 Token
        token_data = client.request_token_with_client_credentials()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        logger.info("🎉 步骤 1：成功向授权服务器获取初始 DPoP Token！")

        # 5. 演示刷新流
        if refresh_token:
            logger.info("--- 正在演示 DPoP 刷新流 (Refresh Flow) ---")
            new_token_data = client.refresh_token(refresh_token)
            access_token = new_token_data.get("access_token")
            logger.info("🎉 步骤 2：成功刷新获取最新 DPoP Token！")

        # 6. 访问受保护的资源服务器 (RS)
        # 👉 注入 W4 策略上下文：绑定合法任务 task-order-001 并启用策略检查
        legit_policy_context = {
            "task_id": "task-order-001",
            "enforce_policy": True
        }
        logger.info(f"--- 步骤 3：携带 Token、合法任务上下文 ({legit_policy_context['task_id']}) 请求受保护业务数据: {RS_URL} ---")
        rs_data = client.get_protected_resource(RS_URL, access_token, context=legit_policy_context)
        
        logger.info("🏆 步骤 3 成功！资源服务器放行，业务响应:")
        logger.info(f">> {rs_data['message']}")
        logger.info(f">> 拿到核心机密数据: {rs_data['data']['secret_data']}")
        logger.info("=== 恭喜！端到端全链路 (Client -> AS -> RS) 100% 验收通关！ ===")

    except Exception as e:
        logger.exception("❌ 流程中断详情:")  # <--- 使用 logger.exception 会自动打印完整堆栈！

if __name__ == "__main__":
    main()
