# 基于安全芯片的 AI Agent 可信授权

用安全芯片（SE）做 AI Agent 的可信授权根：**插上芯片才能授权，拔掉或越权就不能用**。

**主语言：Python ≥ 3.11**（SoftSE / DPoP / 策略门 / pytest 全栈统一；真 SE 侧可用 APDU/PKCS#11 适配，不必换语言）。

技术主线：SE 内保管不可导出私钥 → 按策略签发 **OAuth DPoP（RFC 9449）** 证明 → Agent 代用户访问云服务 / 调用高危工具时无法泄露密钥、无法越权滥用。

## 目标能力

| 目标 | 含义 |
| --- | --- |
| 机密性 | 授权私钥不可被 Agent 导出 |
| 不可挪用 | 绑定持证的令牌离开对应 SE 环境不可用 |
| 防滥用 | 策略外的 proof / 签名请求被芯片侧拒绝 |
| 可插拔 | SoftSE → TPM → 真 SE 可切换，授权能力随卡走 |

## 仓库结构

```
src/agent_auth/
├── backend/           # 统一 CryptoBackend：SoftSE / TPM / RealSE
├── se/                # SoftSE、APDU、PKCS#11、策略门
├── policy/            # 白名单、次数窗、task 绑定
└── dpop/              # DPoP proof（只依赖 backend 接口）
examples/
├── demo_ok.py         # 正常授权链路
└── attacks/           # 泄露 / 重放 / 越权对照
tests/                 # 单测（本地通过后再推）
docs/                  # 公开技术说明（课题研究文档不上库）
```

课题说明书、进度安排、参考文献放在本地桌面目录，**不提交本仓库**。

## 环境

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

或使用 `uv`：

```powershell
uv sync --extra dev
uv run pytest
```

## 三人协作（日常流程）

约定：**本地 IDE 实现 → 本地 `pytest` 通过 → 推分支开 PR → Review 后合入 `main`**。不要直接往 `main` 推未测代码。

1. 克隆并建分支  
   ```powershell
   git clone https://github.com/451gh66922/trusted-agent-crypto.git
   cd trusted-agent-crypto
   git checkout main
   git pull
   git checkout -b feat/你的功能名
   ```
2. 在 Cursor / VS Code 里改代码，本地跑通测试。  
3. 提交并推送分支，开 Pull Request：  
   ```powershell
   git add -A
   git commit -m "简述改了什么、为什么"
   git push -u origin HEAD
   gh pr create
   ```
4. 另一位组员 Review；CI / 本地测试通过后再合并。

### 建议分工

| 角色 | 目录 / 范围 |
| --- | --- |
| 芯片与接口 | `src/agent_auth/se/`、`backend/` |
| 协议与客户端 | `src/agent_auth/dpop/`、Keycloak/Google 对接、`examples/demo_ok.py` |
| 攻击与评测 | `examples/attacks/`、`tests/`、对比表与演示脚本 |

### 分支命名

| 类型 | 前缀 | 示例 |
| --- | --- | --- |
| 新功能 | `feat/` | `feat/soft-se-dpop` |
| 修复 | `fix/` | `fix/policy-whitelist` |
| 文档 | `docs/` | `docs/architecture` |
| 重构 | `refactor/` | `refactor/backend-api` |

### 禁止提交

`tokens.json`、`credentials.json`、`.env`、私钥、真实 refresh token。
