"""策略相关类型定义。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PolicyConfig:
    """芯片侧可固化的策略配置。"""

    allowed_hosts: list[str] = field(default_factory=list)
    allowed_scopes: list[str] = field(default_factory=list)
    allowed_recipients: list[str] = field(default_factory=list)
    max_ops_per_day: int | None = None
    task_id: str | None = None
    intent_hash: str | None = None
