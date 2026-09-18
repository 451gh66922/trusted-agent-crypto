"""审计日志按 task_id 回放。

用法：python tools/replay_audit.py --log audit.jsonl --task TASK_ID [--verify]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_auth.audit.chain import verify_chain


def replay(path: Path, task_id: str | None, verify: bool = False) -> int:
    if not path.exists():
        print(f"log file not found: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    if verify:
        ok = verify_chain(lines)
        print(f"chain {'OK' if ok else 'FAIL'}: {path}")
        if not ok:
            return 1
    count = 0
    for line in lines:
        obj = json.loads(line)
        if task_id is not None and obj.get("task_id") != task_id:
            continue
        t = obj.get("timestamp", "")
        d = obj.get("decision", "")
        r = obj.get("reason_code") or ""
        h = obj.get("htu", "")
        rec = obj.get("recipient", "") or ""
        print(f"{t}  {d:4}  {r:24}  htu={h}  recipient={rec}  task_id={obj.get('task_id')}")
        count += 1
    if count == 0:
        label = f"task_id={task_id}" if task_id is not None else "all"
        print(f"no records for {label} in {path}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay audit JSONL by task_id")
    parser.add_argument("--log", default="audit.jsonl", help="JSONL audit log path")
    parser.add_argument("--task", default=None, dest="task", help="filter by task_id")
    parser.add_argument("--verify", action="store_true", help="verify hash chain before replay")
    args = parser.parse_args()
    raise SystemExit(replay(Path(args.log), args.task, args.verify))
