"""
W4 核心演示：密钥使用点策略门 (PolicyGate) 效果对照。
演示内容：
1. 正常请求 (合法 task_id + 白名单目标) -> 放行并成功访问；
2. 越权攻击 (恶意目标/注入诱导) -> 密钥使用点硬拒绝 (POLICY_DENIED)，不靠 Prompt！
"""
import os
import logging
from agent_auth.backend.factory import get_crypto_backend
from agent_auth.dpop.client import AgentDPoPClient
from agent_auth.dpop.exceptions import PolicyDeniedError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PolicyTest")

TOKEN_URL = "http://localhost:8080/realms/crypto-contest/protocol/openid-connect/token"
CLIENT_ID = os.getenv("CLIENT_ID", "agent-app")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

def run_policy_demo():
    print("=" * 65)
    print("🛡️  启动 W4 密钥使用点策略硬门 (PolicyGate) 防御效果演示")
    print("=" * 65)

    # 使用支持策略校验的后端
    backend = get_crypto_backend("software")
    client = AgentDPoPClient(backend, TOKEN_URL, CLIENT_ID, CLIENT_SECRET)

    # 1. 正常业务场景 (合规操作)
    print("\n👉 [场景 A] 合法 Agent 执行合规任务 (task-order-001 -> 内部业务 RS)")
    legit_context = {
        "task_id": "task-order-001",
        "enforce_policy": True
    }
    try:
        # 获取受保护资源
        proof = backend.make_dpop_proof(
            htm="GET", 
            htu="http://127.0.0.1:9999/api/protected-resource", 
            context=legit_context
        )
        print("   ✅ 策略门放行：签名成功！合规业务 Proof 已生成。")
    except PolicyDeniedError as e:
        print(f"   ❌ 意外被拦截: {e}")

    # 2. 模拟越权/滥用攻击场景 (被 Prompt 注入诱导，试图向外部恶意地址泄露数据)
    print("\n👉 [场景 B] Agent 遭受 Prompt 注入，试图越权向恶意地址发起签名...")
    malicious_context = {
        "task_id": "task-injected-999",
        "enforce_policy": True
    }
    evil_url = "http://evil-attacker.com/steal-data"
    
    try:
        proof = backend.make_dpop_proof(
            htm="POST", 
            htu=evil_url, 
            context=malicious_context
        )
        print("   ❌ 警告：越权签名居然成功了！(防御失效)")
    except PolicyDeniedError as e:
        print(f"   🛑 密钥使用点防御生效！硬拦截成功:")
        print(f"      • 拦截原因: {e.reason}")
        print(f"      • 错误代码: {e.reason_code}")
        print("   ✅ 验证通过：拒绝发生在私钥使用点，黑客改 Prompt 彻底失效！")

    print("\n" + "=" * 65)

if __name__ == "__main__":
    run_policy_demo()
