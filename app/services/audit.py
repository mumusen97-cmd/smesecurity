import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


AUDIT_PATH = Path("data") / "audit.log"


def append_audit(event: str, actor_role: str, details: Dict[str, str]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "actor_role": actor_role,
        "details": details,
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def read_audit() -> List[dict]:
    if not AUDIT_PATH.exists():
        return []
    rows: List[dict] = []
    with AUDIT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows
