"""Traffic key / IV derivation (RFC 8446 §7.3)."""

from __future__ import annotations

from dataclasses import dataclass

from tacrypto.base import CryptoSuite
from tacrypto.tls.hkdf_label import hkdf_expand_label

# TLS_AES_128_GCM_SHA256
AES_128_GCM_KEY_LEN = 16
AES_GCM_IV_LEN = 12


@dataclass(frozen=True, slots=True)
class TrafficKeys:
    key: bytes
    iv: bytes


def traffic_keys(
    suite: CryptoSuite,
    traffic_secret: bytes,
    *,
    key_length: int = AES_128_GCM_KEY_LEN,
    iv_length: int = AES_GCM_IV_LEN,
) -> TrafficKeys:
    """Derive ``[sender]_write_key`` and ``[sender]_write_iv``."""
    key = hkdf_expand_label(suite, traffic_secret, "key", b"", key_length)
    iv = hkdf_expand_label(suite, traffic_secret, "iv", b"", iv_length)
    return TrafficKeys(key=key, iv=iv)


def next_traffic_secret(suite: CryptoSuite, secret: bytes) -> bytes:
    """``application_traffic_secret_N+1`` (RFC 8446 §7.2)."""
    hash_len = len(suite.hash(b""))
    return hkdf_expand_label(suite, secret, "traffic upd", b"", hash_len)
