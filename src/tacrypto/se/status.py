"""ISO/IEC 7816-4 status words used by the SE simulator."""

from __future__ import annotations

SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_SECURITY_STATUS = 0x6982
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA = 0x6A80
SW_FILE_NOT_FOUND = 0x6A82
SW_REF_NOT_FOUND = 0x6A88
SW_INS_NOT_SUPPORTED = 0x6D00
SW_CLA_NOT_SUPPORTED = 0x6E00


class SeError(Exception):
    """Raised by the Host client when SW != 9000."""

    def __init__(self, sw: int, message: str = "") -> None:
        self.sw = sw
        detail = message or f"SE status word {sw:04X}"
        super().__init__(detail)
