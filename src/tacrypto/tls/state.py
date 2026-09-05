"""Shared TLS peer state machine helpers."""

from __future__ import annotations

from enum import Enum, auto

from tacrypto.tls.exporter import tls_exporter

# RFC 9266-style exporter label for channel binding material.
CHANNEL_BINDING_EXPORTER_LABEL = "EXPORTER-Channel-Binding"
DEFAULT_EXPORTER_CONTEXT = b"trusted-agent-merchant"
DEFAULT_EXPORTER_LENGTH = 32


class HandshakeState(Enum):
    INIT = auto()
    WAIT_SERVER_HELLO = auto()
    WAIT_SERVER_FLIGHT = auto()
    WAIT_CLIENT_FINISHED = auto()
    CONNECTED = auto()
    CLOSED = auto()


class TlsError(RuntimeError):
    """Protocol / state-machine error."""


def derive_channel_binding(suite, exporter_master_secret: bytes) -> bytes:
    return tls_exporter(
        suite,
        exporter_master_secret,
        CHANNEL_BINDING_EXPORTER_LABEL,
        DEFAULT_EXPORTER_CONTEXT,
        DEFAULT_EXPORTER_LENGTH,
    )
