import json
import os
import time
from typing import Any, Dict

_LOG_PATH = os.path.join(os.path.dirname(__file__), "data", "oauth_connections.jsonl")


def _safe_text(value: Any, max_len: int = 200) -> str:
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def log_event(event: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
    payload = {"ts": int(time.time()), **event}
    with open(_LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")


def safe_error_detail(detail: Any, max_len: int = 200) -> str:
    return _safe_text(detail, max_len=max_len)
