"""Byte-stream record buffer: accumulate and peel TLS records."""

from __future__ import annotations

from tacrypto.tls.record import (
    ContentType,
    RecordError,
    RecordLayer,
    TAG_LEN,
    parse_plaintext,
)


class RecordStream:
    """Incremental parser over a TCP-like byte stream of TLS records."""

    def __init__(self, records: RecordLayer) -> None:
        self.records = records
        self._buf = bytearray()

    def feed(self, data: bytes) -> None:
        self._buf.extend(data)

    def __len__(self) -> int:
        return len(self._buf)

    def try_read(self) -> tuple[ContentType, bytes] | None:
        """Return one decrypted/plaintext record, or None if incomplete."""
        if len(self._buf) < 5:
            return None
        length = int.from_bytes(self._buf[3:5], "big")
        total = 5 + length
        if len(self._buf) < total:
            return None
        chunk = bytes(self._buf[:total])
        del self._buf[:total]

        if (
            chunk[0] == int(ContentType.APPLICATION_DATA)
            and self.records.read_keys is not None
            and length >= TAG_LEN
        ):
            ctype, content, rest = self.records.open(chunk)
            if rest:
                raise RecordError("internal: open returned remainder on exact chunk")
            return ctype, content

        rec, rest = parse_plaintext(chunk)
        if rest:
            raise RecordError("internal: plaintext parse remainder on exact chunk")
        return rec.content_type, rec.fragment

    def read_all(self) -> list[tuple[ContentType, bytes]]:
        out: list[tuple[ContentType, bytes]] = []
        while True:
            item = self.try_read()
            if item is None:
                break
            out.append(item)
        return out
