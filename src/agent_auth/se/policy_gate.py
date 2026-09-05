"""芯片侧策略门：白名单 / 次数窗 / task 绑定。

即使 LLM 护栏失败，此处仍可拒签。
"""

from __future__ import annotations

from typing import Any


class PolicyGate:
    """在 SoftSE / SE 内（或严格 TCB 适配层）执行硬策略。"""

    def allow(self, *, operation: str, context: dict[str, Any]) -> bool:
        raise NotImplementedError
