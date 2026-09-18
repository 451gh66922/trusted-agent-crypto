"""
自动化回归巡检脚本 (高级版)：
全覆盖验证：历史测试文件 + 三种安全后端形态 (SoftSE / Software / 拔卡模拟)。
"""
import os
import sys
import time
import subprocess

# 定义巡检任务：(任务名称, 执行路径, 环境变量, 预期结果类型)
# expected: "PASS" 代表预期正常跑完，"EXPECT_UNPLUGGED_BLOCK" 代表预期必须被拔卡拦截
TEST_CASES = [
    ("1. 历史兼容: Bearer Token 验证", "examples/test_token_bearer.py", {}, "PASS"),
    ("2. 历史兼容: DPoP Token 探针", "examples/test_token_dpop.py", {}, "PASS"),
    ("3. 主链路: SoftSE 安全后端形态", "examples/demo_ok.py", {"AUTH_BACKEND": "soft_se"}, "PASS"),
    ("4. 基线对照: 传统软件私钥形态", "examples/demo_ok.py", {"AUTH_BACKEND": "software"}, "PASS"),
    ("5. 插拔模拟: 卸载/拔除后端形态", "examples/demo_ok.py", {"AUTH_BACKEND": "unplugged"}, "EXPECT_UNPLUGGED_BLOCK"),
]

def run_case(name: str, path: str, env_vars: dict, expected: str) -> bool:
    print(f"\n👉 [正在巡检] {name}...")
    start_time = time.time()
    
    # 合并当前系统环境变量与测试用例指定的变量
    current_env = os.environ.copy()
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
                print(f"   ✅ PASS: 全链路正常放行 200 OK (耗时 {duration:.2f}s)")
                return True
            else:
                print(f"   ❌ FAIL: 流程意外中断 (耗时 {duration:.2f}s)")
                print(f"   [错误详情]: {res.stderr.strip() or res.stdout.strip()}")
                return False

        elif expected == "EXPECT_UNPLUGGED_BLOCK":
            # 拔卡模拟：预期必须被 HARDWARE_NOT_PRESENT 拦截才算合格！
            output = res.stdout + res.stderr
            if "HARDWARE_NOT_PRESENT" in output:
                print(f"   ✅ PASS: 成功模拟物理拔除，硬件不在场防御生效！(耗时 {duration:.2f}s)")
                return True
            else:
                print(f"   ❌ FAIL: 拔除状态下居然未被防御拦截！")
                return False

    except Exception as e:
        print(f"   ❌ ERROR: 运行时异常: {e}")
        return False

def main():
    print("=" * 68)
    print("🚀 启动全自动化回归测试与安全形态体检套件")
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
        print("🎉 恭喜！全套 5 项矩阵测试 100% 满分通过！三种后端形态防御边界清晰！")
        sys.exit(0)
    else:
        print("⚠️ 存在异常用例，请排查！")
        sys.exit(1)

if __name__ == "__main__":
    main()
