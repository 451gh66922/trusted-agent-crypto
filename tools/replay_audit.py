"""审计日志按 task_id 回放小工具（可选哈希链校验）。

用法：
  python tools/replay_audit.py --log audit.jsonl --task TASK_ID
  python tools/replay_audit.py --log audit.jsonl --verify
"""

from agent_auth.audit.replay import replay

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Replay audit JSONL by task_id")
    parser.add_argument("--log", default="audit.jsonl", help="JSONL audit log path")
    parser.add_argument("--task", default=None, dest="task", help="filter by task_id")
    parser.add_argument("--verify", action="store_true", help="verify hash chain before replay")
    args = parser.parse_args()
    raise SystemExit(replay(Path(args.log), args.task, args.verify))
