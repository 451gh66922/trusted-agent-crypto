"""Command / response APDU encode & decode (short form, ISO 7816-4)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandApdu:
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = b""
    le: int | None = None

    def encode(self) -> bytes:
        header = bytes((self.cla & 0xFF, self.ins & 0xFF, self.p1 & 0xFF, self.p2 & 0xFF))
        if not self.data and self.le is None:
            return header
        if self.data and self.le is None:
            if len(self.data) > 255:
                raise ValueError("short APDU data must be <= 255 bytes")
            return header + bytes((len(self.data),)) + self.data
        if not self.data and self.le is not None:
            le = 0 if self.le == 256 else self.le
            if not (0 <= le <= 255):
                raise ValueError("short APDU Le must be 0..255 (0 means 256)")
            return header + bytes((le,))
        if len(self.data) > 255:
            raise ValueError("short APDU data must be <= 255 bytes")
        le = 0 if self.le == 256 else int(self.le)
        if not (0 <= le <= 255):
            raise ValueError("short APDU Le must be 0..255 (0 means 256)")
        return header + bytes((len(self.data),)) + self.data + bytes((le,))


@dataclass(frozen=True, slots=True)
class ResponseApdu:
    data: bytes
    sw: int

    @property
    def ok(self) -> bool:
        return self.sw == 0x9000

    def encode(self) -> bytes:
        return self.data + bytes(((self.sw >> 8) & 0xFF, self.sw & 0xFF))


def parse_command(raw: bytes) -> CommandApdu:
    if len(raw) < 4:
        raise ValueError("command APDU too short")
    cla, ins, p1, p2 = raw[0], raw[1], raw[2], raw[3]
    body = raw[4:]
    if not body:
        return CommandApdu(cla, ins, p1, p2)
    if len(body) == 1:
        le = 256 if body[0] == 0 else body[0]
        return CommandApdu(cla, ins, p1, p2, le=le)
    lc = body[0]
    if len(body) == 1 + lc:
        return CommandApdu(cla, ins, p1, p2, data=body[1:])
    if len(body) == 2 + lc:
        le_byte = body[-1]
        le = 256 if le_byte == 0 else le_byte
        return CommandApdu(cla, ins, p1, p2, data=body[1:-1], le=le)
    raise ValueError("malformed command APDU")


def parse_response(raw: bytes) -> ResponseApdu:
    if len(raw) < 2:
        raise ValueError("response APDU too short")
    sw = (raw[-2] << 8) | raw[-1]
    return ResponseApdu(data=raw[:-2], sw=sw)
