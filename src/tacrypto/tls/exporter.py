"""TLS 1.3 Exporters (RFC 8446 §7.5)."""

from __future__ import annotations

from tacrypto.base import CryptoSuite
from tacrypto.tls.hkdf_label import derive_secret, hkdf_expand_label


def tls_exporter(
    suite: CryptoSuite,
    exporter_master_secret: bytes,
    label: str | bytes,
    context_value: bytes,
    key_length: int,
) -> bytes:
    """``TLS-Exporter(label, context_value, key_length)``.

    Uses ``exporter_master_secret`` (or early exporter master) as ``Secret``::

        TLS-Exporter(label, context_value, key_length) =
            HKDF-Expand-Label(
                Derive-Secret(Secret, label, ""),
                "exporter",
                Hash(context_value),
                key_length)
    """
    if key_length <= 0:
        raise ValueError("key_length must be positive")
    secret = derive_secret(suite, exporter_master_secret, label, b"")
    context_hash = suite.hash(context_value)
    return hkdf_expand_label(suite, secret, "exporter", context_hash, key_length)
