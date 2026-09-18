# 基于安全芯片的 AI Agent 可信授权

用安全芯片（SE）做 AI Agent 的可信授权根：**插上芯片才能授权，拔掉或越权就不能用**。

> **实现定位**：本仓库以 **SoftSE 软件安全元件** 为主路径实现可信授权；以 **SoftSE + 可插拔模拟（卸载后端 = 拔卡）** 形态呈现。

**主语言：Python ≥ 3.11**（SoftSE / DPoP / 策略门 / 审计日志 / pytest 全栈统一）。

技术主线：SE 内保管不可导出私钥 → **策略门在密钥使用点强制校验** → 按策略签发 **OAuth DPoP（RFC 9449）** 证明 → **每次签名/拒签落审计日志可回放** → Agent 代用户访问云服务 / 调用高危工具时无法泄露密钥、无法越权滥用、事后可追溯。

## 目标能力

| 目标 | 含义 | 对应验收 |
| --- | --- | --- |
| 机密性 | 授权私钥不可被 Agent 导出（无 `export_private`） | `attack_exfil`：软件基线可偷，SoftSE 无可偷之物 |
| 不可挪用 | 绑定持证的令牌离开对应 SE 环境不可用（jkt 绑定） | `attack_replay_token`：token 拷走重放 401 |
| 防滥用 | 策略外的 proof / 签名请求在**密钥使用点被拒绝**，不靠 Prompt | `attack_abuse`：无策略可越权 / 有策略 `POLICY_DENIED` |
| 可追溯 | 每次签名/拒签落结构化审计日志，可按 `task_id` 回放 | 三类攻击的拒绝证据均可从日志摘录 |
| 可插拔 | 统一 `CryptoBackend` 接口，`卸载后端 = 拔卡` 可现场演示 | 授权根可控：卸载即失败、重挂即恢复 |

## 仓库结构

```
src/agent_auth/
├── backend/           # 统一 CryptoBackend 接口：SoftSE 主实现，TPM 仅 stub + 插拔模拟
├── se/                # SoftSE 内核、策略门 PolicyGate
├── policy/            # 白名单、次数窗、task_id / intent 绑定
├── audit/             # 审计日志：JSONL 追加写、哈希链防篡改（可选）、按 task_id 回放
└── dpop/              # DPoP proof（只依赖 backend 接口，签名经 SeDPoPKey 适配类委托后端）
examples/
├── demo_ok.py         # 正常授权链路（Keycloak DPoP 主舞台）
└── attacks/           # 泄露 / 重放 / 越权对照（attack_exfil / attack_replay_token / attack_abuse）
tests/                 # 单测 + 攻击回归（本地通过后再推）
docs/                  # 公开技术说明（课题研究文档不上库）
tools/
└── replay_audit.py    # 审计日志按 task_id 回放小工具（可选哈希链校验）
```

## 核心增量（相对相关工作 arXiv:2608.06130 等）

1. **可插拔后端**：客户端只依赖 `CryptoBackend` 接口，`GET_PUB` 出 JWK 供 jkt 绑定 / `SIGN` 出 ES256 签名，无导出通道。
2. **密钥使用点策略硬门（PolicyGate v1，W4）**：主机/scope/收件人白名单、次数窗、`task_id` 绑定，拒签立即返回明确原因码。
3. **全程审计日志（W5）**：签名/拒签追加写 JSONL（时间、`task_id`、`htu`、收件人、决策、原因码），可选前条哈希链防篡改 + 回放工具，一键对应对比表拒绝证据。

> 国密/双栈（SM2/SM3）为 P2 可选：来不及则以文档级双栈说明 + 移植点呈现，不阻塞 P0。

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
   git commit -m "feat(r1| r2| r3): 简述改了什么、为什么"
   git push -u origin HEAD
   gh pr create
   ```
4. 另一位组员 Review；CI / 本地测试通过后再合并。**接口变更由 R1 提 RFC 式 PR 说明，R2/R3 同周适配**；跨目录改动须目录主人批准。

### 分工

| 角色 | 目录 / 范围 | 主交付物 |
| --- | --- | --- |
| R1 后端 | `src/agent_auth/se/`、`backend/`、`policy/`、审计日志 | SoftSE + 统一后端 + 插拔模拟；PolicyGate + 审计日志 |
| R2 协议 | `src/agent_auth/dpop/`、授权服务器对接、`examples/demo_ok.py` | DPoP 正确性；Keycloak 主链路 |
| R3 评测 | `examples/attacks/`、`tests/` 协同、竞赛材料 | 三类攻击脚本 + 对比表；说明书/海报/视频 |

### 分支命名

| 类型 | 前缀 | 示例 |
| --- | --- | --- |
| 新功能 | `feat/` | `feat/soft-se-dpop` |
| 修复 | `fix/` | `fix/policy-whitelist` |
| 文档 | `docs/` | `docs/architecture` |
| 重构 | `refactor/` | `refactor/backend-api` |

### 禁止提交

`tokens.json`、`credentials.json`、`.env`、私钥、真实 refresh token。日志样例进提交包前必须脱敏。

