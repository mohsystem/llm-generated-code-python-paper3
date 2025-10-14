
import re
import hashlib
import threading
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict
import json

class Task132:
    MAX_LOG_SIZE = 10000
    MAX_EVENT_LENGTH = 1000
    LOG_FILE = "security_events.log"
    
    def __init__(self):
        self.events = []
        self.event_counters = defaultdict(int)
        self.lock = threading.RLock()
        self.date_format = "%Y-%m-%d %H:%M:%S"
        
    def _sanitize_input(self, input_str: str) -> str:
        """Sanitize input to prevent log injection"""
        if input_str is None:
            return ""
        
        # Limit length
        if len(input_str) > self.MAX_EVENT_LENGTH:
            input_str = input_str[:self.MAX_EVENT_LENGTH]
        
        # Remove control characters and newlines
        sanitized = re.sub(r'[\\n\\r\\t]', ' ', input_str)
        sanitized = re.sub(r'[^\\x20-\\x7E]', '', sanitized)
        
        return sanitized.strip()
    
    def _is_valid_severity(self, severity: str) -> bool:
        """Validate severity level"""
        valid_levels = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        return severity.upper() in valid_levels
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        if not ip:
            return False
        
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip))
    
    def log_event(self, event_type: str, description: str, 
                  severity: str, source_ip: str) -> bool:
        """Log security event with validation"""
        with self.lock:
            try:
                # Validate inputs
                if not event_type or not description or not severity:
                    return False
                
                # Sanitize all inputs
                clean_event_type = self._sanitize_input(event_type)
                clean_description = self._sanitize_input(description)
                clean_severity = self._sanitize_input(severity)
                clean_source_ip = self._sanitize_input(source_ip)
                
                # Validate severity level
                if not self._is_valid_severity(clean_severity):
                    return False
                
                # Validate IP format if provided
                if clean_source_ip and not self._is_valid_ip(clean_source_ip):
                    return False
                
                timestamp = datetime.now()
                event = {
                    'timestamp': timestamp.strftime(self.date_format),
                    'event_type': clean_event_type,
                    'description': clean_description,
                    'severity': clean_severity.upper(),
                    'source_ip': clean_source_ip if clean_source_ip else 'N/A'
                }
                
                # Prevent log overflow
                if len(self.events) >= self.MAX_LOG_SIZE:
                    self.events.pop(0)
                
                self.events.append(event)
                self.event_counters[clean_event_type] += 1
                
                # Write to file securely
                self._write_to_file(event)
                
                return True
            except Exception as e:
                print(f"Error logging event: {str(e)}")
                return False
    
    def _write_to_file(self, event: Dict) -> None:
        """Securely write to log file"""
        try:
            with open(self.LOG_FILE, 'a', encoding='utf-8') as f:
                log_entry = f"[{event['timestamp']}] [{event['severity']}] [{event['event_type']}] {event['description']} - Source: {event['source_ip']}\\n"
                f.write(log_entry)
        except IOError as e:
            print(f"Error writing to log file: {str(e)}")
    
    def get_events_by_severity(self, severity: str) -> List[Dict]:
        """Get events by severity level"""
        with self.lock:
            clean_severity = self._sanitize_input(severity).upper()
            return [event for event in self.events 
                   if event['severity'] == clean_severity]
    
    def get_event_count(self, event_type: str) -> int:
        """Get event count by type"""
        clean_event_type = self._sanitize_input(event_type)
        return self.event_counters.get(clean_event_type, 0)
    
    def get_all_events(self) -> List[Dict]:
        """Get all events"""
        with self.lock:
            return self.events.copy()
    
    def _generate_hash(self, data: str) -> str:
        """Generate hash for event integrity"""
        return hashlib.sha256(data.encode()).hexdigest()


def main():
    monitor = Task132()
    
    print("=== Security Event Logging System ===\\n")
    
    # Test Case 1: Valid login failure event
    print("Test Case 1: Login Failure")
    result1 = monitor.log_event("LOGIN_FAILURE", "Failed login attempt for user admin", 
                                "HIGH", "192.168.1.100")
    print(f"Event logged: {result1}")
    
    # Test Case 2: Valid unauthorized access event
    print("\\nTest Case 2: Unauthorized Access")
    result2 = monitor.log_event("UNAUTHORIZED_ACCESS", 
                                "Attempted access to restricted resource", 
                                "CRITICAL", "10.0.0.50")
    print(f"Event logged: {result2}")
    
    # Test Case 3: Invalid severity level (should fail)
    print("\\nTest Case 3: Invalid Severity")
    result3 = monitor.log_event("DATA_BREACH", "Sensitive data accessed", 
                                "INVALID_LEVEL", "172.16.0.1")
    print(f"Event logged: {result3}")
    
    # Test Case 4: Log injection attempt (should be sanitized)
    print("\\nTest Case 4: Log Injection Prevention")
    result4 = monitor.log_event("MALICIOUS_INPUT", 
                                "Test\\nFake Log Entry\\r\\nAnother Line", 
                                "MEDIUM", "192.168.1.50")
    print(f"Event logged: {result4}")
    
    # Test Case 5: Valid firewall block event
    print("\\nTest Case 5: Firewall Block")
    result5 = monitor.log_event("FIREWALL_BLOCK", 
                                "Blocked suspicious traffic", 
                                "LOW", "203.0.113.10")
    print(f"Event logged: {result5}")
    
    # Display all logged events
    print("\\n=== All Logged Security Events ===")
    all_events = monitor.get_all_events()
    for event in all_events:
        print(f"[{event['timestamp']}] [{event['severity']}] [{event['event_type']}] {event['description']} - Source: {event['source_ip']}")
    
    # Display high severity events
    print("\\n=== High Severity Events ===")
    high_events = monitor.get_events_by_severity("HIGH")
    for event in high_events:
        print(f"[{event['timestamp']}] [{event['severity']}] [{event['event_type']}] {event['description']} - Source: {event['source_ip']}")
    
    # Display event counts
    print("\\n=== Event Counts ===")
    print(f"LOGIN_FAILURE: {monitor.get_event_count('LOGIN_FAILURE')}")
    print(f"UNAUTHORIZED_ACCESS: {monitor.get_event_count('UNAUTHORIZED_ACCESS')}")


if __name__ == "__main__":
    main()
