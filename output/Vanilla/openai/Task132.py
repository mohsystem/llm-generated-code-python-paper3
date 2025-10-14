from dataclasses import dataclass
from typing import List, Dict

@dataclass
class Event:
    timestamp: int
    type: str
    severity: int
    source: str
    message: str

class SecurityLogger:
    def __init__(self):
        self.events: List[Event] = []

    def log_event(self, timestamp: int, type: str, severity: int, source: str, message: str) -> int:
        self.events.append(Event(timestamp, type, severity, source, message))
        return len(self.events) - 1

    def total_events(self) -> int:
        return len(self.events)

    def count_by_type(self, type: str) -> int:
        return sum(1 for e in self.events if e.type == type)

    def count_by_severity_at_least(self, min_severity: int) -> int:
        return sum(1 for e in self.events if e.severity >= min_severity)

    def count_from_source(self, source: str) -> int:
        return sum(1 for e in self.events if e.source == source)

    def count_in_range(self, start: int, end: int) -> int:
        return sum(1 for e in self.events if start <= e.timestamp <= end)

    def count_in_window(self, end_time: int, window_seconds: int) -> int:
        start_exclusive = end_time - window_seconds
        return sum(1 for e in self.events if start_exclusive < e.timestamp <= end_time)

    def is_anomalous(self, end_time: int, window_seconds: int, threshold: int) -> bool:
        return self.count_in_window(end_time, window_seconds) > threshold

    def counts_by_type(self) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for e in self.events:
            d[e.type] = d.get(e.type, 0) + 1
        return d

if __name__ == "__main__":
    logger = SecurityLogger()
    t0 = 1700000000

    logger.log_event(t0 + 10, "LOGIN_FAILURE", 3, "web", "Invalid password")
    logger.log_event(t0 + 20, "ACCESS_DENIED", 4, "db", "Unauthorized table access")
    logger.log_event(t0 + 30, "MALWARE_DETECTED", 5, "av", "Trojan found")
    logger.log_event(t0 + 40, "LOGIN_SUCCESS", 1, "web", "User login")
    logger.log_event(t0 + 50, "PORT_SCAN", 4, "ids", "Scan detected")
    logger.log_event(t0 + 55, "LOGIN_FAILURE", 3, "web", "Invalid password")
    logger.log_event(t0 + 58, "LOGIN_FAILURE", 3, "vpn", "Failed login")
    logger.log_event(t0 + 120, "DLP_ALERT", 4, "dlp", "Sensitive data transfer")
    logger.log_event(t0 + 125, "MALWARE_DETECTED", 5, "av", "Worm found")
    logger.log_event(t0 + 180, "ACCESS_DENIED", 2, "db", "Restricted view")

    print("Test1 totalEvents:", logger.total_events())
    print("Test2 countByType(LOGIN_FAILURE):", logger.count_by_type("LOGIN_FAILURE"))
    print("Test3 countBySeverityAtLeast(4):", logger.count_by_severity_at_least(4))
    print("Test4 countInRange[t0, t0+60]:", logger.count_in_range(t0, t0 + 60))
    print("Test5 isAnomalous(window=60, end=t0+60, threshold=6):", logger.is_anomalous(t0 + 60, 60, 6))