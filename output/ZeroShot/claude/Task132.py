
import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Dict
import json
import os

class EventType(Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    DATA_MODIFICATION = "DATA_MODIFICATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SYSTEM_ERROR = "SYSTEM_ERROR"

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SecurityEvent:
    def __init__(self, event_type: EventType, severity: Severity, user_id: str,
                 ip_address: str, description: str, resource_accessed: str):
        self.event_id = self._generate_event_id()
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.severity = severity
        self.user_id = self._sanitize_input(user_id)
        self.ip_address = self._sanitize_input(ip_address)
        self.description = self._sanitize_input(description)
        self.resource_accessed = self._sanitize_input(resource_accessed)
    
    def _generate_event_id(self) -> str:
        return f"EVT-{str(uuid.uuid4())[:8].upper()}"
    
    def _sanitize_input(self, input_str: str) -> str:
        if input_str is None:
            return "N/A"
        return input_str.replace('\\r', ' ').replace('\\n', ' ').strip()
    
    def __str__(self) -> str:
        timestamp_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return (f"[{timestamp_str}] [{self.event_id}] [{self.severity.value}] "
                f"[{self.event_type.value}] User: {self.user_id} | IP: {self.ip_address} | "
                f"Resource: {self.resource_accessed} | Description: {self.description}")

class SecurityLogger:
    def __init__(self, max_buffer_size: int = 100, log_file: str = "security_events.log"):
        self.event_buffer: List[SecurityEvent] = []
        self.max_buffer_size = max_buffer_size
        self.log_file = log_file
    
    def log_event(self, event: SecurityEvent) -> None:
        self.event_buffer.append(event)
        self._write_to_file(event)
        
        if event.severity in [Severity.CRITICAL, Severity.HIGH]:
            print(f"ALERT: {event}")
        
        if len(self.event_buffer) >= self.max_buffer_size:
            self._flush_buffer()
    
    def _write_to_file(self, event: SecurityEvent) -> None:
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(str(event) + '\\n')
        except IOError as e:
            print(f"Error writing to log file: {e}")
    
    def _flush_buffer(self) -> None:
        self.event_buffer.clear()
    
    def get_recent_events(self, count: int) -> List[SecurityEvent]:
        return self.event_buffer[-count:] if count < len(self.event_buffer) else self.event_buffer
    
    def generate_report(self) -> None:
        event_counts: Dict[EventType, int] = {}
        severity_counts: Dict[Severity, int] = {}
        
        for event in self.event_buffer:
            event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
        
        print("\\n=== Security Event Report ===")
        print(f"Total Events: {len(self.event_buffer)}")
        print("\\nEvents by Type:")
        for event_type, count in event_counts.items():
            print(f"  {event_type.value}: {count}")
        print("\\nEvents by Severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity.value}: {count}")
        print("============================\\n")

def main():
    logger = SecurityLogger(100)
    
    # Test Case 1: Login Success
    event1 = SecurityEvent(
        EventType.LOGIN_SUCCESS, Severity.LOW, "user123",
        "192.168.1.100", "User logged in successfully", "/login"
    )
    logger.log_event(event1)
    
    # Test Case 2: Failed Login Attempt
    event2 = SecurityEvent(
        EventType.LOGIN_FAILURE, Severity.MEDIUM, "admin",
        "10.0.0.50", "Failed login attempt - invalid password", "/login"
    )
    logger.log_event(event2)
    
    # Test Case 3: Unauthorized Access Attempt
    event3 = SecurityEvent(
        EventType.UNAUTHORIZED_ACCESS, Severity.HIGH, "user456",
        "172.16.0.200", "Attempted to access restricted resource", "/admin/config"
    )
    logger.log_event(event3)
    
    # Test Case 4: Critical Privilege Escalation
    event4 = SecurityEvent(
        EventType.PRIVILEGE_ESCALATION, Severity.CRITICAL, "user789",
        "203.0.113.42", "Attempted privilege escalation detected", "/admin/users"
    )
    logger.log_event(event4)
    
    # Test Case 5: Data Modification
    event5 = SecurityEvent(
        EventType.DATA_MODIFICATION, Severity.MEDIUM, "user123",
        "192.168.1.100", "Modified user profile settings", "/profile/edit"
    )
    logger.log_event(event5)
    
    # Generate and display report
    logger.generate_report()
    
    print("Recent Events:")
    recent = logger.get_recent_events(3)
    for event in recent:
        print(event)

if __name__ == "__main__":
    main()
