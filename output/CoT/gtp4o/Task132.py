import json
import os
import threading
import time
from datetime import datetime, timezone
from secrets import token_hex
from typing import List, Dict, Tuple


class Severity:
    INFO = "INFO"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"

    ALL = [INFO, WARNING, ALERT, CRITICAL]


class Event:
    __slots__ = ("id", "epoch_millis", "iso8601", "severity", "source", "action", "target", "status", "details")

    def __init__(self, id: str, epoch_millis: int, iso8601: str, severity: str,
                 source: str, action: str, target: str, status: str, details: str):
        self.id = id
        self.epoch_millis = epoch_millis
        self.iso8601 = iso8601
        self.severity = severity
        self.source = source
        self.action = action
        self.target = target
        self.status = status
        self.details = details

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "epochMillis": self.epoch_millis,
            "ts": self.iso8601,
            "severity": self.severity,
            "source": self.source,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "details": self.details,
        }


class SecurityLogger:
    def __init__(self, path: str = "security.log", max_bytes: int = 256 * 1024, max_recent: int = 1000):
        self._path = os.path.abspath(path)
        self._rotated = self._path + ".1"
        self._max_bytes = max_bytes
        self._max_recent = max_recent
        self._lock = threading.Lock()
        self._recent: List[Event] = []
        self._counts: Dict[str, int] = {s: 0 for s in Severity.ALL}

    def log_event(self, source: str, action: str, target: str, status: str, details: str, severity: str) -> Event:
        if severity not in Severity.ALL:
            raise ValueError("invalid severity")
        src = self._sanitize(source) or "unknown"
        act = self._sanitize(action) or "unknown"
        tgt = self._sanitize(target) or "unknown"
        stat = self._sanitize(status) or "unknown"
        det = self._redact_secrets(self._sanitize(details))

        now_ms = int(time.time() * 1000)
        iso = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc).isoformat()
        ev = Event(token_hex(16), now_ms, iso, severity, src, act, tgt, stat, det)

        with self._lock:
            self._rotate_if_needed()
            try:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
            except Exception:
                pass  # best-effort disk logging
            self._recent.append(ev)
            if len(self._recent) > self._max_recent:
                self._recent = self._recent[-self._max_recent:]
            self._counts[severity] += 1
        return ev

    def get_recent_events(self, n: int) -> List[Event]:
        if n <= 0:
            return []
        with self._lock:
            return list(reversed(self._recent))[:n]

    def get_severity_counts(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def detect_anomalies(self, window_seconds: int, threshold_failures_per_source: int) -> List[str]:
        floor = int(time.time() * 1000) - max(1, window_seconds) * 1000
        counts: Dict[str, int] = {}
        with self._lock:
            for e in self._recent:
                if e.epoch_millis >= floor and e.status.upper() == "FAILURE":
                    counts[e.source] = counts.get(e.source, 0) + 1
        alerts = []
        for src, c in counts.items():
            if c >= threshold_failures_per_source:
                alerts.append(f"Anomaly: source={src} failures={c} withinLastSec={window_seconds}")
        return alerts

    def _rotate_if_needed(self) -> None:
        try:
            size = os.path.getsize(self._path) if os.path.exists(self._path) else 0
            if size >= self._max_bytes:
                try:
                    if os.path.exists(self._rotated):
                        os.remove(self._rotated)
                except Exception:
                    pass
                try:
                    if os.path.exists(self._path):
                        os.replace(self._path, self._rotated)
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _sanitize(s: str) -> str:
        if s is None:
            return ""
        out_chars = []
        for ch in s:
            if ch == '\n' or ch == '\r' or ch == '\t' or ord(ch) >= 0x20:
                out_chars.append(ch)
            if len(out_chars) >= 1024:
                break
        return "".join(out_chars).strip()

    @staticmethod
    def _redact_secrets(s: str) -> str:
        if not s:
            return s
        for key in ["password", "token", "secret", "apikey", "api_key", "authorization", "auth"]:
            s = SecurityLogger._redact_key(s, key)
        return s

    @staticmethod
    def _redact_key(s: str, key: str) -> str:
        i = 0
        lower = s.lower()
        k = key.lower()
        res = []
        while i < len(s):
            idx = lower.find(k, i)
            if idx < 0:
                res.append(s[i:])
                break
            res.append(s[i:idx])
            j = idx + len(k)
            while j < len(s) and s[j].isspace():
                j += 1
            if j < len(s) and s[j] == '=':
                j += 1
                while j < len(s) and s[j].isspace():
                    j += 1
                res.append(s[idx:j])
                res.append("******")
                while j < len(s) and s[j] not in ['&', ',', ';'] and not s[j].isspace():
                    j += 1
                i = j
            else:
                res.append(s[idx:idx + len(k)])
                i = idx + len(k)
        return "".join(res)


def main():
    logger = SecurityLogger()
    logger.log_event("auth-service", "LOGIN", "user:alice", "SUCCESS", "login via SSO", Severity.INFO)
    logger.log_event("webapp1", "LOGIN", "user:bob", "FAILURE", "bad credentials password=supersecret", Severity.WARNING)
    logger.log_event("webapp1", "LOGIN", "user:bob", "FAILURE", "ip=10.0.0.5 token=abcd1234", Severity.WARNING)
    logger.log_event("webapp1", "LOGIN", "user:bob", "FAILURE", "too many attempts", Severity.ALERT)
    logger.log_event("ids", "INTRUSION", "host:db1", "DETECTED", "signature matched secret=mysecret; action=blocked", Severity.CRITICAL)

    print("Severity counts:", logger.get_severity_counts())
    print("Recent events:")
    for e in logger.get_recent_events(5):
        print(json.dumps(e.to_dict(), ensure_ascii=False))
    print("Anomalies:")
    for a in logger.detect_anomalies(300, 3):
        print(a)


if __name__ == "__main__":
    main()