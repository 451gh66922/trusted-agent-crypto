"""SE applet: APDU dispatch, key slots, internal crypto only."""

from __future__ import annotations

import os

from tacrypto.base import CryptoSuite
from tacrypto.se.apdu import CommandApdu, ResponseApdu, parse_command
from tacrypto.se.keys import KeyStore, KeyUsage
from tacrypto.se.status import (
    SW_CLA_NOT_SUPPORTED,
    SW_CONDITIONS_NOT_SATISFIED,
    SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED,
    SW_OK,
    SW_REF_NOT_FOUND,
    SW_SECURITY_STATUS,
    SW_WRONG_DATA,
    SW_WRONG_LENGTH,
)

# Trusted Agent SE application identifier
DEFAULT_AID = b"TASE01"

CLA_ISO = 0x00
CLA_PROP = 0x80

INS_SELECT = 0xA4
INS_GET_DATA = 0xCA
INS_GEN_KEY = 0x46
INS_SIGN = 0x2A
INS_GET_CHALLENGE = 0x84
INS_ECDH = 0x86
INS_EXPORT_SECRET = 0x88
INS_SET_BINDING = 0x2B
INS_SIGN_BOUND = 0x2C
INS_GET_PUBLIC = 0xF0
INS_GET_BINDING = 0x2D

P1_KEY_SIGN = 0x01
P1_KEY_ECDH = 0x02


class SeApplet:
    """Software SE applet. Private keys stay inside ``KeyStore``."""

    def __init__(
        self,
        suite: CryptoSuite,
        aid: bytes = DEFAULT_AID,
        *,
        allowed_actions: frozenset[str] | None = None,
        max_amount: int = 10_000,
    ) -> None:
        self.suite = suite
        self.aid = aid
        self.selected = False
        self.keys = KeyStore()
        self._secrets: dict[int, bytes] = {}
        self._next_secret_id = 1
        self._last_challenge = b""
        self._channel_binding: bytes | None = None
        self._allowed_actions = allowed_actions or frozenset(
            {"pay", "transfer", "query"}
        )
        self._max_amount = max_amount
        self._used_nonces: set[bytes] = set()
    def exchange(self, raw: bytes) -> bytes:
        try:
            cmd = parse_command(raw)
        except ValueError:
            return ResponseApdu(b"", SW_WRONG_LENGTH).encode()
        return self.dispatch(cmd).encode()

    def dispatch(self, cmd: CommandApdu) -> ResponseApdu:
        if cmd.cla == CLA_ISO and cmd.ins == INS_SELECT:
            return self._select(cmd)
        if cmd.cla != CLA_PROP:
            return ResponseApdu(b"", SW_CLA_NOT_SUPPORTED)
        if not self.selected:
            return ResponseApdu(b"", SW_SECURITY_STATUS)

        handlers = {
            INS_GET_DATA: self._get_data,
            INS_GEN_KEY: self._gen_key,
            INS_SIGN: self._sign,
            INS_GET_CHALLENGE: self._get_challenge,
            INS_ECDH: self._ecdh,
            INS_EXPORT_SECRET: self._export_secret,
            INS_SET_BINDING: self._set_binding,
            INS_GET_BINDING: self._get_binding,
            INS_SIGN_BOUND: self._sign_bound,
            INS_GET_PUBLIC: self._get_public,
        }
        handler = handlers.get(cmd.ins)
        if handler is None:
            return ResponseApdu(b"", SW_INS_NOT_SUPPORTED)
        return handler(cmd)

    def _select(self, cmd: CommandApdu) -> ResponseApdu:
        if cmd.p1 != 0x04 or cmd.p2 != 0x00:
            return ResponseApdu(b"", SW_WRONG_DATA)
        if cmd.data != self.aid:
            self.selected = False
            return ResponseApdu(b"", SW_FILE_NOT_FOUND)
        self.selected = True
        fci = b"FCI:" + self.aid
        return ResponseApdu(fci, SW_OK)

    def _get_data(self, cmd: CommandApdu) -> ResponseApdu:
        # suite name as ASCII
        name = self.suite.name.encode("ascii")
        return ResponseApdu(name, SW_OK)

    def _gen_key(self, cmd: CommandApdu) -> ResponseApdu:
        if cmd.p1 == P1_KEY_SIGN:
            usage = KeyUsage.SIGN
            pair = self.suite.generate_signing_keypair()
        elif cmd.p1 == P1_KEY_ECDH:
            usage = KeyUsage.ECDH
            pair = self.suite.generate_ephemeral_keypair()
        else:
            return ResponseApdu(b"", SW_WRONG_DATA)
        record = self.keys.insert(usage, pair.private_key, pair.public_key)
        return ResponseApdu(bytes((record.key_id,)) + record.public_key, SW_OK)

    def _sign(self, cmd: CommandApdu) -> ResponseApdu:
        # PSO-like: P1=9E P2=9A, data = key_id || digest
        if cmd.p1 != 0x9E or cmd.p2 != 0x9A:
            return ResponseApdu(b"", SW_WRONG_DATA)
        if len(cmd.data) < 2:
            return ResponseApdu(b"", SW_WRONG_LENGTH)
        key_id = cmd.data[0]
        digest = cmd.data[1:]
        record = self.keys.get(key_id)
        if record is None:
            return ResponseApdu(b"", SW_REF_NOT_FOUND)
        if record.usage != KeyUsage.SIGN:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        signature = self.suite.sign(record.private_key, digest)
        return ResponseApdu(signature, SW_OK)

    def _get_challenge(self, cmd: CommandApdu) -> ResponseApdu:
        n = cmd.le if cmd.le is not None else 16
        n = min(max(n, 1), 32)
        self._last_challenge = os.urandom(n)
        return ResponseApdu(self._last_challenge, SW_OK)

    def _ecdh(self, cmd: CommandApdu) -> ResponseApdu:
        if len(cmd.data) < 2:
            return ResponseApdu(b"", SW_WRONG_LENGTH)
        key_id = cmd.data[0]
        peer_pk = cmd.data[1:]
        record = self.keys.get(key_id)
        if record is None:
            return ResponseApdu(b"", SW_REF_NOT_FOUND)
        if record.usage != KeyUsage.ECDH:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        shared = self.suite.derive_shared_secret(record.private_key, peer_pk)
        if self._next_secret_id > 255:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        handle = self._next_secret_id
        self._next_secret_id += 1
        self._secrets[handle] = shared
        # Return handle only — shared secret stays in SE
        return ResponseApdu(bytes((handle,)), SW_OK)

    def _export_secret(self, cmd: CommandApdu) -> ResponseApdu:
        """Release ECDHE shared secret once for Host-side TLS Key Schedule.

        Long-term signing keys are never exported. The secret handle is
        invalidated after a successful export (one-shot).
        """
        if len(cmd.data) != 1:
            return ResponseApdu(b"", SW_WRONG_LENGTH)
        handle = cmd.data[0]
        secret = self._secrets.pop(handle, None)
        if secret is None:
            return ResponseApdu(b"", SW_REF_NOT_FOUND)
        return ResponseApdu(secret, SW_OK)

    def _set_binding(self, cmd: CommandApdu) -> ResponseApdu:
        """Store TLS channel-binding material for subsequent bound signatures."""
        if not cmd.data or len(cmd.data) > 64:
            return ResponseApdu(b"", SW_WRONG_LENGTH)
        self._channel_binding = cmd.data
        return ResponseApdu(b"", SW_OK)

    def _get_binding(self, cmd: CommandApdu) -> ResponseApdu:
        if self._channel_binding is None:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        return ResponseApdu(self._channel_binding, SW_OK)

    def _sign_bound(self, cmd: CommandApdu) -> ResponseApdu:
        """Sign ``mandate_body || '|' || channel_binding`` with SE-held binding.

        Command data: ``key_id (1) || mandate_body``.
        The Host **cannot** supply channel_binding here; SE always uses the
        value previously installed via ``SET_BINDING``.
        Response: ``binding_len (1) || binding || signature``.
        """
        if cmd.p1 != 0x9E or cmd.p2 != 0x9A:
            return ResponseApdu(b"", SW_WRONG_DATA)
        if self._channel_binding is None:
            return ResponseApdu(b"", SW_SECURITY_STATUS)
        if len(cmd.data) < 2:
            return ResponseApdu(b"", SW_WRONG_LENGTH)
        key_id = cmd.data[0]
        body = cmd.data[1:]
        # Lightweight on-card policy over canonical JSON body
        deny = self._check_mandate_body(body)
        if deny is not None:
            return deny
        record = self.keys.get(key_id)
        if record is None:
            return ResponseApdu(b"", SW_REF_NOT_FOUND)
        if record.usage != KeyUsage.SIGN:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        binding = self._channel_binding
        signed = body + b"|" + binding
        digest = self.suite.hash(signed)
        signature = self.suite.sign(record.private_key, digest)
        if len(binding) > 255:
            return ResponseApdu(b"", SW_WRONG_LENGTH)
        return ResponseApdu(bytes((len(binding),)) + binding + signature, SW_OK)

    def _check_mandate_body(self, body: bytes) -> ResponseApdu | None:
        import json
        import time

        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ResponseApdu(b"", SW_WRONG_DATA)
        action = obj.get("action")
        if action not in self._allowed_actions:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        amount = obj.get("amount")
        if amount is not None:
            if not isinstance(amount, int) or amount < 0 or amount > self._max_amount:
                return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        now = int(time.time())
        not_before = obj.get("not_before")
        if isinstance(not_before, int) and now < not_before:
            return ResponseApdu(b"", SW_CONDITIONS_NOT_SATISFIED)
        expires_at = obj.get("expires_at")
        if isinstance(expires_at, int) and now > expires_at:
            return ResponseApdu(b"", SW_SECURITY_STATUS)
        nonce_hex = obj.get("nonce") or ""
        if nonce_hex:
            try:
                nonce = bytes.fromhex(nonce_hex)
            except ValueError:
                return ResponseApdu(b"", SW_WRONG_DATA)
            if nonce in self._used_nonces:
                return ResponseApdu(b"", SW_SECURITY_STATUS)
            self._used_nonces.add(nonce)
        return None

    def _get_public(self, cmd: CommandApdu) -> ResponseApdu:
        record = self.keys.get(cmd.p2)
        if record is None:
            return ResponseApdu(b"", SW_REF_NOT_FOUND)
        return ResponseApdu(record.public_key, SW_OK)
