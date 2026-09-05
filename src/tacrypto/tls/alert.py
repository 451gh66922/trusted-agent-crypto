"""TLS Alert records (RFC 8446 §6) — simplified two-byte alerts."""

from __future__ import annotations

from enum import IntEnum


class AlertLevel(IntEnum):
    WARNING = 1
    FATAL = 2


class AlertDescription(IntEnum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    HANDSHAKE_FAILURE = 40
    ILLEGAL_PARAMETER = 47
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    PROTOCOL_VERSION = 70
    INTERNAL_ERROR = 80
    MISSING_EXTENSION = 109
    UNSUPPORTED_EXTENSION = 110
    UNKNOWN_PSK_IDENTITY = 115


def encode_alert(level: AlertLevel, description: AlertDescription) -> bytes:
    return bytes((int(level), int(description)))


def parse_alert(payload: bytes) -> tuple[AlertLevel, AlertDescription]:
    if len(payload) != 2:
        raise ValueError("alert payload must be 2 bytes")
    return AlertLevel(payload[0]), AlertDescription(payload[1])
