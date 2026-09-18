# 安全后端形态切换与调用指南

供 R3 评测脚本编写、组内联调及演示使用。

## 一、三种安全形态说明

1. soft_se (默认形态)
   - 生产标准形态。
   - 私钥保留在后端内部，不可导出。
   - 正常签发 DPoP Proof，防御凭据泄露。

2. software (传统软件形态)
   - 故意脆弱的基线对照形态。
   - 暴露私钥导出通道 (export_private_key_vulnerable)。
   - 供 R3 演示进程/文件被读取导致私钥失守的攻击场景。

3. unplugged (拔卡/卸载模拟形态)
   - 模拟安全芯片被拔出或安全模块未就绪。
   - 强制拒绝一切签名请求。
   - 抛出 HARDWARE_NOT_PRESENT 异常，证明授权根不在场。

## 二、命令行 (CLI) 调用方式

在运行主链路或测试脚本时，直接通过 --backend 参数指定模式：

1. 正常运行 SoftSE 链路：
python examples/demo_ok.py --backend soft_se

2. 切换为传统软件基线：
python examples/demo_ok.py --backend software

3. 模拟物理拔卡拦截：
python examples/demo_ok.py --backend unplugged

## 三、环境变量切换方式

在无法修改命令行参数的脚本或独立环境中，通过 AUTH_BACKEND 注入：

1. 运行拔卡模拟：
AUTH_BACKEND=unplugged python examples/demo_ok.py

2. 运行软件私钥模式：
AUTH_BACKEND=software python examples/demo_ok.py

## 四、Python 代码级调用 (供 R3 脚本直接引用)

R3 同学在编写 attack_exfil.py 等攻击脚本时，可直接导入工厂函数：

from agent_auth.backend.factory import get_crypto_backend

# 实例化拔卡环境：
backend = get_crypto_backend("unplugged")

# 实例化软件基线环境：
backend = get_crypto_backend("software")

## 五、一键自动化回归自检

运行以下命令，自动测试全部 5 种兼容性与安全形态组合，并输出报告：

python tools/run_all_checks.py
