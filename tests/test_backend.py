"""后端抽象接口测试。"""

import pytest

from agent_auth.backend.base import CryptoBackend


def test_crypto_backend_cannot_instantiate() -> None:
    with pytest.raises(TypeError):
        CryptoBackend()  # type: ignore[abstract]
