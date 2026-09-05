# SE 功能切割表

面向可信 AI Agent 软件仿真：Host 侧跑协议与业务，SE 侧保管密钥并执行敏感密码运算。通信走 ISO/IEC 7816-4 APDU（软件仿真）。

## 分层

```
Agent / TLS 状态机（Host）
        │  语义 API：key_id、digest、公钥……
        ▼
SeClient（Host）—— 编解码 APDU
        │  CLA INS P1 P2 [Lc Data] [Le]
        ▼
SeApplet（SE 仿真）—— 选应用、密钥槽、策略
        │  内部调用，私钥永不出现在 APDU
        ▼
tacrypto.CryptoSuite（intl | gm）
```

## 切割总表

| 功能 | 位置 | 理由 | APDU / 语义接口 |
|------|------|------|-----------------|
| 选应用 (AID) | SE | 多应用隔离入口 | `00 A4 04 00` + AID → FCI |
| 查询套件信息 | SE | 告知 Host 当前 intl/gm | `80 CA 00 00` → suite 名 |
| 长期身份密钥生成 | SE | 私钥不可导出 | `80 46 01 00` → `key_id \|\| pk` |
| 临时 ECDH 密钥生成 | SE | 握手私钥留在卡内 | `80 46 02 00` → `key_id \|\| pk` |
| Mandate / 授权签名 | SE | 高价值签名，私钥不出卡 | `80 2A 9E 9A` + `key_id \|\| digest` → sig |
| ECDH 共享秘密派生 | SE | 带私钥运算 | `80 86 00 00` + `key_id \|\| peer_pk` → handle |
| 取随机挑战 | SE | 抗重放材料 | `80 84 00 00` → nonce |
| 读取公钥 | SE | 仅导出公钥 | `80 F0 00 xx`（P2=`key_id`）→ pk |
| 大块 mandate 哈希 | Host | 体积大、非保密 | Host 本地 `suite.hash` / SHA-256·SM3 |
| TLS 记录分帧 / 状态机 | Host | 协议逻辑 | 无 APDU |
| 会话 AEAD（大数据） | Host（默认可） | 性能；高保证可再收回 SE | 见 `tls.record` / 第 3 周加固 |
| TLS Key Schedule / Exporter | Host（本周） | RFC 8446；输入来自 SE ECDHE | 见 [tls-partition.md](tls-partition.md) |
| ECDHE 临时私钥 | SE | 私钥不出卡 | `80 46 02 00` / `80 86` |
| ECDHE 会话秘密释放（仿真） | SE → Host | 供 Host 跑 Key Schedule；一次性 | `80 88` + handle |
| Agent 业务 / 工具调用 | Host | 非密码边界 | 无 APDU |
| PIN / 使用策略 | SE + Host 策略引擎 | 控制谁能签、签什么 | `SET_BINDING` / `SIGN_BOUND` + `PolicyEngine` |
| Channel Binding | TLS Exporter → SE | 防信道-授权脱节 | 见 [policy-channel-binding.md](policy-channel-binding.md) |

## 明确不进 APDU 的内容

- 任何 `private_key` / 原始签名私钥字节
- 把 `CryptoSuite.sign(sk, …)` 之类「密钥当参数」的原语直接透传给 Host

## 本仓库垂直切片（已实现）

1. Host `SELECT` → `GEN_IDENTITY` → 本地哈希 mandate → `SIGN`
2. Host 用返回的公钥验签
3. 测试断言：密钥槽内私钥从未出现在任何 APDU 响应中
