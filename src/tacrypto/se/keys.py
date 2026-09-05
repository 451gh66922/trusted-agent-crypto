"""In-SE key slot store — private keys never leave this module via APDU."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class KeyUsage(str, Enum):
    SIGN = "sign"
    ECDH = "ecdh"


@dataclass(slots=True)
class KeyRecord:
    key_id: int
    usage: KeyUsage
    private_key: bytes
    public_key: bytes


class KeyStore:
    """Opaque key slots addressed by a one-byte key_id."""

    def __init__(self) -> None:
        self._keys: dict[int, KeyRecord] = {}
        self._next_id = 1

    def insert(self, usage: KeyUsage, private_key: bytes, public_key: bytes) -> KeyRecord:
        if self._next_id > 255:
            raise RuntimeError("key store full")
        key_id = self._next_id
        self._next_id += 1
        record = KeyRecord(
            key_id=key_id,
            usage=usage,
            private_key=private_key,
            public_key=public_key,
        )
        self._keys[key_id] = record
        return record

    def get(self, key_id: int) -> KeyRecord | None:
        return self._keys.get(key_id)

    def public_material_snapshot(self) -> list[tuple[int, KeyUsage, bytes]]:
        """Host-visible view: key_id, usage, public_key only."""
        return [(k.key_id, k.usage, k.public_key) for k in self._keys.values()]
