import threading
import time
from enum import Enum
from collections import deque, defaultdict
from typing import List, Dict


class Level(Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"


class Event:
    __slots__ = ("id", "timestamp_ms", "level", "type", "source", "message")

    def __init__(self, eid: int, timestamp_ms: int, level: Level, etype: str, source: str, message: str):
        self.id = eid
        self.timestamp_ms = timestamp_ms
        self.level = level
        self.type = etype
        self.source = source
        self.message = message

    def __repr__(self):
        return f"Event(id={self.id}, ts={self.timestamp_ms}, level={self.level.value}, type='{self.type}', source='{self.source}', message='{self.message}')"


class SecurityLoggerMonitor:
    def __init__(self, max_events: int = 1024, brute_force_window_ms: int = 300000, brute_force_threshold: int = 4):
        self._lock = threading.RLock()
        self._events: deque[Event] = deque()
        self._max_events = max(1, int(max_events))
        self._stats: Dict[Level, int] = {lvl: 0 for lvl in Level}
        self._failed_map: Dict[str, deque[int]] = defaultdict(deque)
        self._brute_window = int(brute_force_window_ms)
        self._brute_threshold = max(1, int(brute_force_threshold))
        self._next_id = 1

    @staticmethod
    def _sanitize(s: str, max_len: int) -> str:
        if s is None:
            return ""
        out_chars = []
        last_space = False
        for ch in s:
            if len(out_chars) >= max_len:
                break
            o = ord(ch)
            if ch in ("\r", "\n"):
                if not last_space:
                    out_chars.append(' ')
                    last_space = True
            elif 32 <= o < 127:
                out_chars.append(ch)
                last_space = False
            elif ch.isspace():
                if not last_space:
                    out_chars.append(' ')
                    last_space = True
            # ignore other control chars
        return ''.join(out_chars)

    def _append_event_locked(self, e: Event) -> None:
        self._events.append(e)
        self._stats[e.level] += 1
        while len(self._events) > self._max_events:
            rem = self._events.popleft()
            self._stats[rem.level] = max(0, self._stats[rem.level] - 1)

    def log_event(self, source: str, etype: str, level: Level, message: str, timestamp_ms: int | None = None) -> int:
        s_source = self._sanitize(source, 64)
        s_type = self._sanitize(etype, 64)
        s_msg = self._sanitize(message, 1024)
        ts = int(timestamp_ms if timestamp_ms is not None and timestamp_ms > 0 else time.time() * 1000)

        with self._lock:
            eid = self._next_id
            self._next_id += 1
            e = Event(eid, ts, level, s_type, s_source, s_msg)
            self._append_event_locked(e)

            if s_type == "failed_login":
                dq = self._failed_map[s_source]
                dq.append(ts)
                cutoff = ts - self._brute_window
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if len(dq) >= self._brute_threshold:
                    aeid = self._next_id
                    self._next_id += 1
                    amsg = self._sanitize(f"Brute force suspected for source={s_source} count={len(dq)}", 256)
                    alert = Event(aeid, ts, Level.ALERT, "alert_bruteforce", s_source, amsg)
                    self._append_event_locked(alert)
            return e.id

    def get_recent_events(self, limit: int) -> List[Event]:
        lim = max(0, int(limit))
        with self._lock:
            return list(list(self._events)[-lim:]) if lim > 0 else []

    def get_stats(self) -> Dict[Level, int]:
        with self._lock:
            return dict(self._stats)

    def get_alerts_since(self, since_timestamp_ms: int) -> List[Event]:
        with self._lock:
            return [e for e in self._events if e.level == Level.ALERT and e.timestamp_ms >= since_timestamp_ms]


def main():
    mon = SecurityLoggerMonitor(max_events=1024, brute_force_window_ms=300000, brute_force_threshold=4)
    now = int(time.time() * 1000)

    # Test case 1
    mon.log_event("user1", "login_success", Level.INFO, "User logged in", now + 10)
    # Test case 2
    mon.log_event("userX", "failed_login", Level.ERROR, "Bad password attempt 1", now + 20)
    # Test case 3
    mon.log_event("userX", "failed_login", Level.ERROR, "Bad password attempt 2", now + 30)
    # Test case 4
    mon.log_event("userX", "failed_login", Level.ERROR, "Bad password attempt 3", now + 40)
    # Test case 5 - triggers alert
    mon.log_event("userX", "failed_login", Level.ERROR, "Bad password attempt 4", now + 50)

    print("Stats:")
    for k, v in mon.get_stats().items():
        print(k.value, v)

    print("Recent events:")
    for e in mon.get_recent_events(10):
        print(e)

    print("Alerts since now:")
    for e in mon.get_alerts_since(now):
        print(e)


if __name__ == "__main__":
    main()