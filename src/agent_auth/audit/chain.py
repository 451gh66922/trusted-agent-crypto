"""审计日志哈希链（P2 选配，防篡改）。

每条日志含前条哈希；篡改任一条日志链校验失败。
回退：来不及实现可在提交包用文档级说明 + 移植点呈现。
"""

from __future__ import annotations

import hashlib
import json


def chain_hash(prev_digest: str | None, record_json: str) -> str:
    h = hashlib.sha256()
    if prev_digest is not None:
        h.update(prev_digest.encode("utf-8"))
    h.update(record_json.encode("utf-8"))
    return h.hexdigest()


def verify_chain(lines: list[str]) -> bool:
    prev: str | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        obj = json.loads(stripped)
        digest = obj.get("_chain") or obj.get("chain_digest")
        payload = {k: v for k, v in obj.items() if k not in ("_chain", "chain_digest")}
        expected = chain_hash(prev, json.dumps(payload, ensure_ascii=False, sort_keys=True))
        if digest is None:
            prev = expected
            continue
        if digest != expected:
            return False
        prev = digest
    return True
