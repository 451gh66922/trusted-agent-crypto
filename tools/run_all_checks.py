"""
自动化回归巡检脚本：
一键测试当前环境下所有客户端链路与旧文件的可用性，输出健康度报告。
"""
import subprocess
import sys
import time

TEST_SCRIPTS = [
    ("旧版 Bearer Token 验证", "examples/test_token_bearer.py"),
    ("旧版 DPoP Token 验证", "examples/test_token_dpop.py"),
    ("W2 终极端到端主链路 (demo_ok)", "examples/demo_ok.py"),
]

def run_script(name: str, path: str) -> bool:
    print(f"\n👉 [正在测试] {name} ({path})...")
    start_time = time.time()
    try:
        # 执行脚本，隔离输出
        result = subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            timeout=15
        )
        duration = time.time() - start_time
        if result.returncode == 0:
            print(f"   ✅ PASS (耗时 {duration:.2f}s)")
            return True
        else:
            print(f"   ❌ FAIL (耗时 {duration:.2f}s)")
            print(f"   [错误详情]:\n{result.stderr.strip() or result.stdout.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"   ❌ TIMEOUT (超过 15 秒未响应)")
        return False
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False

def main():
    print("=" * 60)
    print("🚀 启动全自动化回归测试 (Regression Check Suite)")
    print("=" * 60)

    summary = []
    for name, path in TEST_SCRIPTS:
        success = run_script(name, path)
        summary.append((name, success))

    print("\n" + "=" * 60)
    print("📊 巡检结果总览:")
    print("=" * 60)
    all_passed = True
    for name, success in summary:
        status = "✅ 通过 (OK)" if success else "❌ 异常 (FAILED)"
        print(f"  • {name.ljust(35)}: {status}")
        if not success:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("🎉 全部测试 100% 通过！环境健康，无历史代码破坏！")
        sys.exit(0)
    else:
        print("⚠️ 存在失败用例，请根据上方详情检查！")
        sys.exit(1)

if __name__ == "__main__":
    main()
