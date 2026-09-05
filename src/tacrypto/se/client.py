"""Host-side SE client: semantic API over APDU (never sees private keys)."""

from __future__ import annotations

from dataclasses import dataclass

from tacrypto.se.apdu import CommandApdu, ResponseApdu, parse_response
from tacrypto.se.applet import (
    CLA_ISO,
    CLA_PROP,
    DEFAULT_AID,
    INS_ECDH,
    INS_EXPORT_SECRET,
    INS_GEN_KEY,
    INS_GET_BINDING,
    INS_GET_CHALLENGE,
    INS_GET_DATA,
    INS_GET_PUBLIC,
    INS_SELECT,
    INS_SET_BINDING,
    INS_SIGN,
    INS_SIGN_BOUND,
    P1_KEY_ECDH,
    P1_KEY_SIGN,
    SeApplet,
)
from tacrypto.se.status import SW_OK, SeError


@dataclass(frozen=True, slots=True)
class PublicKeyRef:
    key_id: int
    public_key: bytes


class SeClient:
    """Thin Host wrapper around ``SeApplet.exchange``."""

    def __init__(self, applet: SeApplet) -> None:
        self._applet = applet
        self._transcript: list[tuple[bytes, bytes]] = []

    @property
    def applet(self) -> SeApplet:
        return self._applet

    @property
    def transcript(self) -> list[tuple[bytes, bytes]]:
        """Captured (command, response) APDU pairs for tests / demos."""
        return list(self._transcript)

    def exchange(self, cmd: CommandApdu) -> ResponseApdu:
        raw_cmd = cmd.encode()
        raw_rsp = self._applet.exchange(raw_cmd)
        self._transcript.append((raw_cmd, raw_rsp))
        rsp = parse_response(raw_rsp)
        if rsp.sw != SW_OK:
            raise SeError(rsp.sw)
        return rsp

    def select(self, aid: bytes | None = None) -> bytes:
        target = aid if aid is not None else self._applet.aid
        rsp = self.exchange(CommandApdu(CLA_ISO, INS_SELECT, 0x04, 0x00, data=target))
        return rsp.data

    def get_suite_name(self) -> str:
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_GET_DATA, 0x00, 0x00, le=32))
        return rsp.data.decode("ascii")

    def gen_identity_key(self) -> PublicKeyRef:
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_GEN_KEY, P1_KEY_SIGN, 0x00, le=256))
        return PublicKeyRef(key_id=rsp.data[0], public_key=rsp.data[1:])

    def gen_ephemeral_key(self) -> PublicKeyRef:
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_GEN_KEY, P1_KEY_ECDH, 0x00, le=256))
        return PublicKeyRef(key_id=rsp.data[0], public_key=rsp.data[1:])

    def sign_mandate(self, key_id: int, digest: bytes) -> bytes:
        if not (0 <= key_id <= 255):
            raise ValueError("key_id must fit in one byte")
        data = bytes((key_id,)) + digest
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_SIGN, 0x9E, 0x9A, data=data, le=256))
        return rsp.data

    def set_channel_binding(self, binding: bytes) -> None:
        if not binding or len(binding) > 64:
            raise ValueError("channel binding must be 1..64 bytes")
        self.exchange(
            CommandApdu(CLA_PROP, INS_SET_BINDING, 0x00, 0x00, data=binding)
        )

    def get_channel_binding(self) -> bytes:
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_GET_BINDING, 0x00, 0x00, le=64))
        return rsp.data

    def sign_bound_mandate(self, key_id: int, body: bytes) -> tuple[bytes, bytes]:
        """Ask SE to attach stored channel_binding and sign ``body``.

        Returns ``(channel_binding, signature)``. Prefer ``MandateService`` for
        the high-level ``BoundMandate`` object.
        """
        if not (0 <= key_id <= 255):
            raise ValueError("key_id must fit in one byte")
        if len(body) > 250:
            raise ValueError("mandate body too large for short APDU")
        data = bytes((key_id,)) + body
        rsp = self.exchange(
            CommandApdu(CLA_PROP, INS_SIGN_BOUND, 0x9E, 0x9A, data=data, le=256)
        )
        if not rsp.data:
            raise SeError(0x6985, "empty bound-sign response")
        blen = rsp.data[0]
        binding = rsp.data[1 : 1 + blen]
        signature = rsp.data[1 + blen :]
        return binding, signature

    def get_challenge(self, length: int = 16) -> bytes:
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_GET_CHALLENGE, 0x00, 0x00, le=length))
        return rsp.data

    def ecdh(self, key_id: int, peer_pk: bytes) -> int:
        data = bytes((key_id,)) + peer_pk
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_ECDH, 0x00, 0x00, data=data, le=1))
        return rsp.data[0]

    def export_secret(self, handle: int) -> bytes:
        """One-shot export of an ECDHE shared secret for Host TLS Key Schedule."""
        if not (0 <= handle <= 255):
            raise ValueError("handle must fit in one byte")
        rsp = self.exchange(
            CommandApdu(CLA_PROP, INS_EXPORT_SECRET, 0x00, 0x00, data=bytes((handle,)), le=256)
        )
        return rsp.data

    def get_public_key(self, key_id: int) -> bytes:
        rsp = self.exchange(CommandApdu(CLA_PROP, INS_GET_PUBLIC, 0x00, key_id, le=256))
        return rsp.data


def connect(
    suite_name: str = "intl",
    aid: bytes = DEFAULT_AID,
    *,
    allowed_actions: frozenset[str] | None = None,
    max_amount: int = 10_000,
) -> SeClient:
    """Create an applet + client bound to ``get_suite(suite_name)``."""
    from tacrypto import get_suite

    applet = SeApplet(
        get_suite(suite_name),
        aid=aid,
        allowed_actions=allowed_actions,
        max_amount=max_amount,
    )
    return SeClient(applet)
