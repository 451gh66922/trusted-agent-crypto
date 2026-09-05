# TLS 1.3 简化仿真：Host / SE 功能切割

面向「SE 内简化 TLS 1.3 + Exporter」与「策略引擎 + Channel Binding」。
Key Schedule / Exporter / Finished 与 [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) §7 一致
（[RFC 8448](https://datatracker.ietf.org/doc/html/rfc8448) KAT）。

## 分层

```
MandateService / Agent（Host）
        │  策略引擎先审金额/动作
        ▼
TlsClient  ←——记录字节——→  MerchantServer     （独立状态机）
   │ ECDHE / EXPORT_SECRET / SET_BINDING / SIGN_BOUND
   ▼
SeApplet（密钥槽 + 卡内策略 + 填入 channel_binding）
   ▼
tacrypto.CryptoSuite（intl | gm）
```

## 切割表

| 步骤 | 位置 | 状态 |
|------|------|------|
| 规范化握手消息 / Transcript | Host | ✅ |
| ECDHE 临时私钥 / 共享秘密 | SE | ✅ |
| Key Schedule / Exporter / Finished | Host | ✅ RFC KAT |
| **正式记录层分帧**（TLSPlaintext / TLSCiphertext） | Host | ✅ `tls.record.RecordLayer` |
| **TlsClient / MerchantServer 状态机** | Host 两端 | ✅ 只交换 record 字节 |
| AEAD 应用数据 | Host 记录层 | ✅ |
| Channel Binding（Exporter） | 两端派生，写入 SE | ✅ |
| 策略引擎（金额/动作/防重放） | Host + SE 双检 | ✅ `policy` |
| Bound mandate 签名（binding 由 SE 填） | SE | ✅ `SIGN_BOUND` |
| 国密 SM4-GCM TLS | — | ⏳ |

## 记录层（RFC 8446 §5）

- 明文：`type || 0x0303 || length || fragment`
- 密文：外层 type=`application_data(23)`；AEAD 明文 = `content || real_type || zeros`；
  AAD = 外层 5 字节头；nonce = `IV XOR seq`

## 独立对等体握手顺序

```
TlsClient.start_handshake()           → ClientHello record
MerchantServer.handle_client_hello()  → ServerHello record
TlsClient.handle_server_hello()
MerchantServer.build_server_flight()  → 加密 flight
TlsClient.handle_server_flight()      → ClientFinished record
MerchantServer.handle_client_finished()
双方 CONNECTED，channel_binding 一致
```

可用 `MemoryTransport.pair()` + `handshake_over_transport` 强制只交换字节；
也可用 `SocketTransport` 做真 TCP 环回。

应用数据经正式记录层：`type||0x0303||len||AEAD(content||type||pad)`。
支持 `close_notify` Alert 与 `RecordStream` 粘包拆包。

## Channel Binding + 策略

1. 握手后两端用 label `EXPORTER-Channel-Binding` 导出 32 字节 binding  
2. Host `SET_BINDING` 写入 SE（此后 Host 无法在签名时偷换）  
3. `PolicyEngine` 审 mandate；通过后 `SIGN_BOUND`：SE 签 `body || '|' || binding`  
4. 商户用公钥 + 自己的 binding 验签  

## 验收

```bash
uv run pytest tests/test_tls_*.py tests/test_policy_mandate.py -q
uv run python examples/tls_merchant_demo.py
```
