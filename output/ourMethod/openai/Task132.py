from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict
import sys

# In-memory event model and logger with validation
ALLOWED_TYPES = {
    "LOGIN_SUCCESS", "LOGIN_FAILURE", "ACCESS_DENIED", "DATA_EXPORT", "MALWARE_ALERT", "CONFIG_CHANGE"
}
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
MIN_TS = 946684800  # 2000-01-01
MAX_TS = 4102444800  # 2100-01-01

@dataclass(frozen=True)
class Event:
    id: int
    timestamp_sec: int
    type: str
    severity: str
    source: str
    message: str

class EventLogger:
    def __init__(self, capacity: int) -> None:
        if not isinstance(capacity, int) or capacity < 1 or capacity > 10000:
            raise ValueError("Invalid capacity")
        self._capacity = capacity
        self._events: List[Event] = []
        self._next_id = 1

    def log_event(self, type_: str, severity: str, source: str, message: str, timestamp_sec: int) -> bool:
        if not self._is_allowed_type(type_) or not self._is_allowed_severity(severity):
            return False
        if not self._is_valid_timestamp(timestamp_sec):
            return False
        if not self._is_valid_source(source, 1, 64):
            return False
        if not self._is_valid_message(message, 1, 256):
            return False
        if len(self._events) >= self._capacity:
            # drop oldest to maintain capacity
            self._events.pop(0)
        ev = Event(self._next_id, timestamp_sec, type_, severity, source, message)
        self._next_id += 1
        self._events.append(ev)
        return True

    def get_events_by_severity(self, severity: str) -> List[Event]:
        if not self._is_allowed_severity(severity):
            return []
        return [e for e in self._events if e.severity == severity]

    def search_by_keyword(self, keyword: str) -> List[Event]:
        if not self._is_valid_keyword(keyword, 1, 32):
            return []
        k = self._to_ascii_lower(keyword)
        out: List[Event] = []
        for e in self._events:
            if k in self._to_ascii_lower(e.message):
                out.append(e)
        return out

    def count_by_type(self) -> Dict[str, int]:
        d: Dict[str, int] = {k: 0 for k in ALLOWED_TYPES}
        for e in self._events:
            d[e.type] = d.get(e.type, 0) + 1
        return d

    def count_by_severity(self) -> Dict[str, int]:
        d: Dict[str, int] = {k: 0 for k in ALLOWED_SEVERITIES}
        for e in self._events:
            d[e.severity] = d.get(e.severity, 0) + 1
        return d

    def get_recent(self, n: int) -> List[Event]:
        if not isinstance(n, int) or n < 0 or n > self._capacity:
            return []
        if n >= len(self._events):
            return list(self._events)
        return self._events[-n:]

    @staticmethod
    def _is_allowed_type(t: str) -> bool:
        return isinstance(t, str) and t in ALLOWED_TYPES

    @staticmethod
    def _is_allowed_severity(s: str) -> bool:
        return isinstance(s, str) and s in ALLOWED_SEVERITIES

    @staticmethod
    def _is_valid_timestamp(ts: int) -> bool:
        return isinstance(ts, int) and MIN_TS <= ts <= MAX_TS

    @staticmethod
    def _is_valid_source(s: str, min_len: int, max_len: int) -> bool:
        if not isinstance(s, str):
            return False
        if not (min_len <= len(s) <= max_len):
            return False
        for ch in s:
            if not (ch.isalnum() or ch in "._-"):
                return False
        return True

    @staticmethod
    def _is_valid_message(s: str, min_len: int, max_len: int) -> bool:
        if not isinstance(s, str):
            return False
        if not (min_len <= len(s) <= max_len):
            return False
        for ch in s:
            if not (32 <= ord(ch) <= 126):
                return False
        return True

    @staticmethod
    def _is_valid_keyword(s: str, min_len: int, max_len: int) -> bool:
        return EventLogger._is_valid_message(s, min_len, max_len)

    @staticmethod
    def _to_ascii_lower(s: str) -> str:
        return "".join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in s)

def format_counts(d: Dict[str, int]) -> str:
    parts = [f"{k}: {d[k]}" for k in sorted(d.keys())]
    return "; ".join(parts)

def main() -> None:
    logger = EventLogger(100)
    base_ts = 1700000000

    # Test 1: valid event
    t1 = logger.log_event("LOGIN_SUCCESS", "INFO", "authsvc", "User alice logged in", base_ts)
    print(f"Test1 success={t1}")

    # Test 2: invalid type
    t2 = logger.log_event("UNKNOWN_TYPE", "LOW", "guard", "Unknown event", base_ts + 1)
    print(f"Test2 success={t2}")

    # Test 3: high severity malware alert
    t3 = logger.log_event("MALWARE_ALERT", "CRITICAL", "scanner01", "Malware signature detected", base_ts + 2)
    print(f"Test3 success={t3}")

    # Test 4: search
    _ = logger.log_event("ACCESS_DENIED", "MEDIUM", "gateway01", "Access denied to resource /admin", base_ts + 3)
    search_res = logger.search_by_keyword("denied")
    print(f"Test4 search count={len(search_res)}")

    # Test 5: counts and recent
    logger.log_event("DATA_EXPORT", "HIGH", "exporter", "Data export initiated", base_ts + 4)
    by_type = logger.count_by_type()
    by_sev = logger.count_by_severity()
    print(f"Test5 countByType: {format_counts(by_type)}")
    print(f"Test5 countBySeverity: {format_counts(by_sev)}")
    recent = logger.get_recent(3)
    print(f"Recent last 3 size={len(recent)}")

if __name__ == "__main__":
    # Avoid unbounded recursion limit changes, no env access
    main()