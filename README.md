# 基于安全芯片的 AI Agent 可信授权

用安全芯片（SE）做 AI Agent 的可信授权根：**插上芯片才能授权，拔掉或越权就不能用**。

技术主线：SE 内保管不可导出私钥 → 按策略签发 **OAuth DPoP（RFC 9449）** 证明 → Agent 代用户访问云服务 / 调用高危工具时无法泄露密钥、无法越权滥用。

## 目标能力

| 目标 | 含义 |
| --- | --- |
| 机密性 | 授权私钥不可被 Agent 导出 |
| 不可挪用 | 绑定持证的令牌离开对应 SE 环境不可用 |
| 防滥用 | 策略外的 proof / 签名请求被芯片侧拒绝 |
| 可插拔 | SoftSE → TPM → 真 SE 可切换，授权能力随卡走 |

## 仓库结构（芯片与接口实施）

```
src/agent_auth/
├── backend/           # 统一 CryptoBackend：SoftSE / TPM / RealSE
├── se/                # 安全芯片侧：SoftSE、APDU、PKCS#11、策略门
├── policy/            # 白名单、次数窗、task 绑定等策略模型
└── dpop/              # DPoP proof 构造（只依赖 backend 接口）
examples/
├── demo_ok.py         # 正常授权链路演示
└── attacks/           # 泄露 / 重放 / 越权对照实验
tests/                 # SoftSE、后端切换、策略门、DPoP 单测
docs/                  # 公开技术说明（课题研究文档不上库）
```

课题说明书、进度安排、参考文献等研究材料放在本地桌面目录，**不提交到本仓库**。

## 环境

要求：Python ≥ 3.11。

```powershell
uv sync --extra dev
# 或
pip install -e ".[dev]"
```

```powershell
pytest
```

## 协作

1. 不要直接 push 到 `main`，从最新 `main` 拉功能分支。
2. 推送后开 Pull Request，Review 后再合并。
3. 凭据文件（`tokens.json`、`credentials.json`、`.env`、密钥）严禁提交。

### 分支命名

| 类型 | 前缀 | 示例 |
| --- | --- | --- |
| 新功能 | `feat/` | `feat/soft-se-dpop` |
| 修复 | `fix/` | `fix/policy-whitelist` |
| 文档 | `docs/` | `docs/architecture` |
| 重构 | `refactor/` | `refactor/backend-api` |
