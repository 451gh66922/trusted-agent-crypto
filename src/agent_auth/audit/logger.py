"""审计日志落盘：签名/拒签追加写 JSONL。

字段对齐 06 计划：时间、task_id、htu、收件人、决策、原因码。
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class AuditRecord:
    """单条签名/拒签决策记录。"""

    task_id: str | None
    htu: str
    recipient: str | None
    decision: Literal["allow", "deny"]
    reason_code: str | None = None
    timestamp: str = field(default_factory=lambda: __import__("datetime").datetime.now().isoformat(timespec="seconds"))


class AuditLogger:
    """追加写 JSONL；日志样例进提交包前必须脱敏。"""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("agent_auth.audit")

    def record(self, entry: AuditRecord) -> None:
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        self._logger.debug("audit: %s %s", entry.decision, entry.htu)
