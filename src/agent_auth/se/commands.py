"""SE 最小命令集约定。

仅暴露：
  - GET_PUB
  - MAKE_DPOP_PROOF
  - SIGN_IF_ALLOWED
明确禁止：EXPORT_KEY
"""

from __future__ import annotations

from enum import Enum


class SECommand(Enum):
    GET_PUB = "GET_PUB"
    MAKE_DPOP_PROOF = "MAKE_DPOP_PROOF"
    SIGN_IF_ALLOWED = "SIGN_IF_ALLOWED"
