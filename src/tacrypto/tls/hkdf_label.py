"""RFC 8446 §7.1 HKDF-Expand-Label and Derive-Secret."""

from __future__ import annotations

from tacrypto.base import CryptoSuite

_TLS13_PREFIX = b"tls13 "


def hkdf_label(length: int, label: bytes | str, context: bytes) -> bytes:
    """Encode the ``HkdfLabel`` struct used by HKDF-Expand-Label."""
    if isinstance(label, str):
        label = label.encode("ascii")
    full_label = _TLS13_PREFIX + label
    if not (0 <= length <= 0xFFFF):
        raise ValueError("length must fit in uint16")
    if len(full_label) > 255:
        raise ValueError("label too long")
    if len(context) > 255:
        raise ValueError("context too long")
    return (
        length.to_bytes(2, "big")
        + bytes((len(full_label),))
        + full_label
        + bytes((len(context),))
        + context
    )


def hkdf_expand_label(
    suite: CryptoSuite,
    secret: bytes,
    label: bytes | str,
    context: bytes,
    length: int,
) -> bytes:
    """``HKDF-Expand-Label(Secret, Label, Context, Length)``."""
    return suite.hkdf_expand(secret, hkdf_label(length, label, context), length)


def derive_secret(
    suite: CryptoSuite,
    secret: bytes,
    label: bytes | str,
    messages_or_hash: bytes,
    *,
    messages_already_hashed: bool = False,
) -> bytes:
    """``Derive-Secret(Secret, Label, Messages)``.

    When ``messages_already_hashed`` is True, ``messages_or_hash`` is treated as
    the transcript hash itself (useful for empty-string context = Hash(\"\")).
    """
    hash_len = len(suite.hash(b""))
    if messages_already_hashed:
        transcript_hash = messages_or_hash
        if len(transcript_hash) != hash_len:
            raise ValueError("transcript hash has unexpected length")
    else:
        transcript_hash = suite.hash(messages_or_hash)
    return hkdf_expand_label(suite, secret, label, transcript_hash, hash_len)
