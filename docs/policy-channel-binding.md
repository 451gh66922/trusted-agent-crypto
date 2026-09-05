# 策略引擎与 Channel Binding

## 目标

任务表里程碑 3：密钥不出 SE；签名对象中的 `channel_binding` **由 SE 填入**；
Host 策略引擎限制动作/金额；错误请求被拒绝并给出原因。

## 组件

| 模块 | 职责 |
|------|------|
| `PolicyEngine` | Host：动作/金额/币种/agent/merchant、时间窗、nonce、速率限制、binding |
| `MandateRequest` | 不含 binding 的规范 JSON body |
| `SeApplet.SET_BINDING` | 存入 TLS Exporter 导出的 binding |
| `SeApplet.SIGN_BOUND` | 强制使用卡内 binding；卡内再检动作/金额/过期/nonce |
| `MandateService` | 串联：策略 → SE 签名 |
| `MerchantVerifier` | 商户：binding 对齐 + 验签 + 可选本地策略 |
| `BoundMandate` | `body + binding + signature` |

## TLS 独立对等体

```
TlsClient  --MemoryTransport/Socket-->  MerchantServer
   │ 只交换 TLS 记录字节
   ▼
SE：ECDHE + SET_BINDING + SIGN_BOUND
```

握手后两端 `channel_binding`（Exporter `EXPORTER-Channel-Binding`）必须一致。

## 拒绝路径（可演示）

| 攻击/异常 | 结果 |
|-----------|------|
| 金额超限 | `amount_exceeded` / SE `6985` |
| 未知动作 | `action_not_allowed` |
| 商户不在白名单 | `merchant_not_allowed` |
| 未设置 binding 就签名 | SE `6982` |
| nonce 重放 | `nonce_replay` / SE `6982` |
| 速率超限 | `rate_limited` |
| **信道重定向**（A 上签的 mandate 交给 B） | `binding_mismatch` |
| 验签失败 | `bad_signature` |

## 验收

```bash
uv run pytest tests/test_tls_peers.py tests/test_tls_transport.py tests/test_policy_mandate.py -q
uv run python examples/tls_merchant_demo.py
```
