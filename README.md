# tacrypto — Trusted Agent Crypto

面向可信 AI Agent 的双栈密码学抽象层（国际算法栈 + 国密算法栈），用于模拟
Agent 安全元件（SE）、TLS 安全通道与策略授权体系。

## 项目结构

```
src/tacrypto/
├── base.py            # 基础抽象接口
├── types.py           # 公共类型定义
├── gm/                # 国密算法套件 (SM2/SM3/SM4)
├── intl/              # 国际算法套件 (AES-GCM 等)
├── tls/               # TLS 1.3 实现（握手、密钥调度、记录层、HKDF 等）
├── se/                # 安全元件仿真（APDU、Applet、密钥管理）
└── policy/            # 策略引擎与授权凭证 (mandate)
docs/                  # 各模块设计文档
examples/              # 演示脚本（TLS 商户演示、DPoP Gmail 等）
tests/                 # pytest 测试（含 RFC 8448 / NIST 测试向量）
```

## 环境搭建

要求：Python ≥ 3.11，推荐使用 [uv](https://docs.astral.sh/uv/)。

```powershell
# 安装依赖（含国密支持与开发工具）
uv sync --extra gm --extra dev

# 或使用 pip
pip install -e ".[gm,dev]"
```

## 运行测试

```powershell
pytest
```

## 协作流程（三人小组）

1. **不要直接 push 到 `main`**，从最新的 `main` 拉出功能分支：

   ```bash
   git checkout main
   git pull origin main
   git checkout -b feat/你的功能名
   ```

2. 本地开发并提交，测试通过后推送到远端：

   ```bash
   git push -u origin feat/你的功能名
   ```

3. 在 GitHub 上发起 **Pull Request** 到 `main`，由组长（或其他成员）Review 后合并。

4. 定期从 `main` 同步自己的分支，减少冲突：

   ```bash
   git fetch origin
   git rebase origin/main
   ```

### 分支命名约定

| 类型   | 前缀        | 示例                    |
| ------ | ----------- | ----------------------- |
| 新功能 | `feat/`     | `feat/tls-client-auth`  |
| 修复   | `fix/`      | `fix/record-padding`    |
| 文档   | `docs/`     | `docs/se-partition`     |
| 重构   | `refactor/` | `refactor/policy-types` |

### 注意事项

- 凭据类文件（`tokens.json`、`credentials.json`、`.env`、密钥文件）已在
  `.gitignore` 中排除，**严禁提交真实凭据**；示例请写入 `*.example.json`。
- `examples/dpop_gmail/` 中如需运行完整示例，参考
  `credentials.example.json` 自行配置本地凭据（不会被提交）。
