"""Dual-stack crypto abstraction package."""

from __future__ import annotations

from tacrypto.base import CryptoSuite
from tacrypto.intl import IntlCryptoSuite
from tacrypto.types import AeadResult, KeyPair


def get_suite(name: str) -> CryptoSuite:
    """Return a concrete suite by name (``intl`` | ``gm``)."""
    normalized = name.strip().lower()
    if normalized == "intl":
        return IntlCryptoSuite()
    if normalized == "gm":
        try:
            from tacrypto.gm import GmCryptoSuite
        except ImportError as exc:
            raise ImportError(
                "GM suite requires optional dependency: uv sync --extra gm"
            ) from exc
        return GmCryptoSuite()
    raise ValueError(f"unknown crypto suite: {name!r}")


__all__ = [
    "AeadResult",
    "CryptoSuite",
    "IntlCryptoSuite",
    "KeyPair",
    "get_suite",
]

try:
    from tacrypto.gm import GmCryptoSuite as GmCryptoSuite

    __all__.append("GmCryptoSuite")
except ImportError:
    pass
