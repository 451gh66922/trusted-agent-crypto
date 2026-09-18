"""
自动化回归巡检脚本 (W1 ~ W4 全矩阵体检版)：
全覆盖验证：
1. 历史兼容: Bearer Token 链路
2. 历史兼容: DPoP Token 探针
3. 主链路: SoftSE 安全后端形态 (带策略上下文)
4. 基线对照: 传统软件私钥形态
5. 插拔模拟: 卸载/拔除安全后端拦截 (HARDWARE_NOT_PRESENT)
6. 策略硬门: 密钥使用点越权拦截 (POLICY_DENIED)
"""
import os
import sys
import time
import subprocess

# 定义巡检用例矩阵：(用例名称, 目标脚本, 注入环境变量, 预期结果类型)
# "PASS": 预期返回码为 0
# "EXPECT_UNPLUGGED_BLOCK": 预期必须抛出 HARDWARE_NOT_PRESENT
TEST_CASES = [
    ("1. 历史兼容: Bearer Token 验证", "examples/test_token_bearer.py", {}, "PASS"),
    ("2. 历史兼容: DPoP Token 探针", "examples/test_token_dpop.py", {}, "PASS"),
    ("3. 主链路: SoftSE 安全后端形态", "examples/demo_ok.py", {"AUTH_BACKEND": "soft_se"}, "PASS"),
    ("4. 基线对照: 传统软件私钥形态", "examples/demo_ok.py", {"AUTH_BACKEND": "software"}, "PASS"),
    ("5. 插拔模拟: 卸载/拔除后端拦截", "examples/demo_ok.py", {"AUTH_BACKEND": "unplugged"}, "EXPECT_UNPLUGGED_BLOCK"),
    ("6. 策略硬门: 密钥使用点越权拦截", "examples/test_policy_gate.py", {}, "PASS"),
]

def run_case(name: str, path: str, env_vars: dict, expected: str) -> bool:
    print(f"\n👉 [正在巡检] {name}...")
    start_time = time.time()
    
    current_env = os.environ.copy()
    # 强制清除本地请求的所有代理环境变量，避免连接超时
    for proxy_key in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
        current_env.pop(proxy_key, None)
    current_env["NO_PROXY"] = "localhost,127.0.0.1,192.168.*,10.*"
    current_env.update(env_vars)

    try:
        res = subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            timeout=15,
            env=current_env
        )
        duration = time.time() - start_time

        if expected == "PASS":
            if res.returncode == 0:
                print(f"   ✅ PASS: 全流程正常放行 (耗时 {duration:.2f}s)")
                return True
            else:
                print(f"   ❌ FAIL: 执行异常中断 (耗时 {duration:.2f}s)")
                print(f"   [错误输出]:\n{res.stderr.strip() or res.stdout.strip()}")
                return False

        elif expected == "EXPECT_UNPLUGGED_BLOCK":
            output = res.stdout + res.stderr
            if "HARDWARE_NOT_PRESENT" in output:
                print(f"   ✅ PASS: 成功模拟拔卡，硬件不在场防御生效！(耗时 {duration:.2f}s)")
                return True
            else:
                print(f"   ❌ FAIL: 拔除状态下未触发预期硬件拦截！")
                return False

    except Exception as e:
        print(f"   ❌ ERROR: 巡检运行异常: {e}")
        return False

def main():
    print("=" * 68)
    print("🚀 启动全自动化回归测试套件 (W1 ~ W4 架构体检)")
    print("=" * 68)

    summary = []
    for name, path, env_vars, expected in TEST_CASES:
        ok = run_case(name, path, env_vars, expected)
        summary.append((name, ok))

    print("\n" + "=" * 68)
    print("📊 巡检结果总览报告:")
    print("=" * 68)
    all_passed = True
    for name, ok in summary:
        status = "✅ PASS" if ok else "❌ FAILED"
        print(f"  • {name.ljust(45)}: {status}")
        if not ok:
            all_passed = False

    print("=" * 68)
    if all_passed:
        print("🎉 恭喜！全量 6 项测试矩阵 100% 全部通过！系统具备极高鲁棒性！")
        sys.exit(0)
    else:
        print("⚠️ 存在失败用例，请根据上方详情检查！")
        sys.exit(1)

if __name__ == "__main__":
    main()
