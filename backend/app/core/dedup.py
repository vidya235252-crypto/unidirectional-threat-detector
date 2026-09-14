from datetime import datetime, timezone
from typing import Dict, Tuple

DedupKey = Tuple[str, str]


class Deduplicator:
    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._last_seen: Dict[DedupKey, datetime] = {}

    def should_suppress(self, flow_id: str, threat_class: str) -> bool:
        key = (flow_id, threat_class)
        now = datetime.now(timezone.utc)

        last = self._last_seen.get(key)
        self._last_seen[key] = now

        if last is None:
            return False

        elapsed = (now - last).total_seconds()
        return elapsed < self.window_seconds