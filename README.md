# tacrypto

Dual-stack crypto + software SE simulation for a trusted AI Agent.

- **intl / gm**: dual crypto suites
- **se**: APDU applet — long-term keys never leave; bound mandates fill channel_binding on-card
- **tls**: Key Schedule (RFC 8446/8448), formal record layer, `TlsClient` ↔ `MerchantServer` over transports
- **policy**: Host policy engine + SE-bound signing + merchant verifier (incl. channel-redirect reject)

## Quick start

```python
from tacrypto import get_suite
from tacrypto.se import connect
from tacrypto.tls import TlsClient, MerchantServer, MemoryTransport, handshake_over_transport
from tacrypto.policy import MandateRequest, MandateService, MerchantVerifier
import os

suite = get_suite("intl")
se = connect("intl")
se.select()
identity = se.gen_identity_key()

client, merchant = TlsClient(suite, se=se), MerchantServer(suite)
c_tx, m_tx = MemoryTransport.pair()
handshake_over_transport(client, merchant, c_tx, m_tx)

svc = MandateService(suite, se, identity)
svc.install_channel_binding(client.channel_binding)
bound = svc.authorize_and_sign(
    MandateRequest(action="pay", agent_id="cashier", amount=100, nonce=os.urandom(8))
)
assert MerchantVerifier(
    suite,
    expected_binding=merchant.channel_binding,
    agent_public_key=identity.public_key,
).verify(bound).ok
```

Docs: [SE](docs/se-partition.md) · [TLS](docs/tls-partition.md) · [Policy](docs/policy-channel-binding.md)

```bash
uv sync --extra dev
uv run pytest
uv run python examples/tls_merchant_demo.py
```
