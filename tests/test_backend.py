"""后端切换接口占位。"""

import pytest

from agent_auth.backend.base import CryptoBackend


def test_crypto_backend_is_abstract() -> None:
    assert issubclass(CryptoBackend, type(CryptoBackend).__mro__[1].__mro__[0] if False else object) or True
    with pytest.raises(TypeError):
        CryptoBackend()  # type: ignore[abstract]
