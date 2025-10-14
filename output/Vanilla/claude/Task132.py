
from datetime import datetime
from collections import defaultdict
from typing import List, Dict

class SecurityEvent:
    def __init__(self, event_type, severity, source, description):
        self.event_type = event_type
        self.severity = severity
        self.source = source
        self.description = description
        self.timestamp = datetime.now()
    
    def __str__(self):
        timestamp_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp_str}] [{self.severity}] [{self.event_type}] {self.source} - {self.description}"

class SecurityMonitor:
    def __init__(self):
        self.event_log = []
        self.event_counts = defaultdict(int)
        self.severity_counts = defaultdict(int)
    
    def log_event(self, event_type, severity, source, description):
        event = SecurityEvent(event_type, severity, source, description)
        self.event_log.append(event)
        
        self.event_counts[event_type] += 1
        self.severity_counts[severity] += 1
        
        print(f"Logged: {event}")
        return event
    
    def get_events_by_severity(self, severity):
        return [event for event in self.event_log if event.severity == severity]
    
    def get_events_by_type(self, event_type):
        return [event for event in self.event_log if event.event_type == event_type]
    
    def get_event_statistics(self):
        return dict(self.event_counts)
    
    def get_severity_statistics(self):
        return dict(self.severity_counts)
    
    def get_all_events(self):
        return self.event_log.copy()
    
    def get_total_events(self):
        return len(self.event_log)
    
    def generate_report(self):
        print("\\n=== Security Event Report ===")
        print(f"Total Events: {self.get_total_events()}")
        print("\\nEvents by Type:")
        for event_type, count in self.event_counts.items():
            print(f"  {event_type}: {count}")
        print("\\nEvents by Severity:")
        for severity, count in self.severity_counts.items():
            print(f"  {severity}: {count}")
        print("============================\\n")

def main():
    monitor = SecurityMonitor()
    
    # Test Case 1: Log authentication failure
    print("Test Case 1: Authentication Failure")
    monitor.log_event("AUTH_FAILURE", "HIGH", "192.168.1.100", "Failed login attempt for user 'admin'")
    
    # Test Case 2: Log successful login
    print("\\nTest Case 2: Successful Login")
    monitor.log_event("AUTH_SUCCESS", "INFO", "192.168.1.101", "User 'john.doe' logged in successfully")
    
    # Test Case 3: Log unauthorized access attempt
    print("\\nTest Case 3: Unauthorized Access")
    monitor.log_event("UNAUTHORIZED_ACCESS", "CRITICAL", "192.168.1.105", "Attempt to access restricted resource")
    
    # Test Case 4: Log multiple events and generate report
    print("\\nTest Case 4: Multiple Events")
    monitor.log_event("AUTH_FAILURE", "HIGH", "192.168.1.102", "Brute force attack detected")
    monitor.log_event("DATA_ACCESS", "MEDIUM", "192.168.1.103", "Sensitive data accessed by user 'jane.smith'")
    monitor.log_event("AUTH_FAILURE", "HIGH", "192.168.1.100", "Another failed login for 'admin'")
    
    monitor.generate_report()
    
    # Test Case 5: Query events by severity
    print("Test Case 5: Query High Severity Events")
    high_severity_events = monitor.get_events_by_severity("HIGH")
    print(f"High Severity Events: {len(high_severity_events)}")
    for event in high_severity_events:
        print(f"  {event}")
    
    print("\\nQuery Events by Type (AUTH_FAILURE):")
    auth_failures = monitor.get_events_by_type("AUTH_FAILURE")
    print(f"Authentication Failures: {len(auth_failures)}")

if __name__ == "__main__":
    main()
