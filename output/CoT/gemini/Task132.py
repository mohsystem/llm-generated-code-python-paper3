import time
from collections import defaultdict

class SecurityEvent:
    """Represents a single security event."""
    def __init__(self, event_type, user_id, source_ip, description):
        # Basic validation
        if not all([event_type, user_id, source_ip, description]):
            raise ValueError("Event fields cannot be empty.")
        
        self.timestamp = int(time.time())
        self.event_type = event_type
        self.user_id = user_id
        self.source_ip = source_ip
        self.description = description

    def __str__(self):
        return (f"Event(time={self.timestamp}, type='{self.event_type}', "
                f"user='{self.user_id}', ip='{self.source_ip}', "
                f"desc='{self.description}')")

class SecurityLogger:
    """Handles the logging of security events."""
    def __init__(self):
        # Note: This in-memory list is not thread-safe.
        self.event_log = []

    def _sanitize(self, input_str):
        """Sanitizes strings to prevent log injection."""
        if not isinstance(input_str, str):
            return ""
        # Replace newline characters to prevent log entry splitting.
        return input_str.replace('\n', '_').replace('\r', '_')

    def log_event(self, event_type, user_id, source_ip, description):
        """Logs a new security event after sanitizing inputs."""
        event = SecurityEvent(
            self._sanitize(event_type),
            self._sanitize(user_id),
            self._sanitize(source_ip),
            self._sanitize(description)
        )
        self.event_log.append(event)
        return event

    def get_event_log(self):
        """Returns a copy of the event log."""
        return list(self.event_log)

    def print_logs(self):
        """Prints all logged events to the console."""
        print("--- Security Event Log ---")
        if not self.event_log:
            print("No events logged.")
        else:
            for event in self.event_log:
                print(event)
        print("--------------------------\n")

class SecurityMonitor:
    """Monitors logs for suspicious patterns."""
    FAILED_LOGIN_THRESHOLD = 3
    TIME_WINDOW_SECONDS = 60

    def analyze_logs(self, events):
        """
        Analyzes a list of security events for patterns like brute-force attacks.
        """
        print("--- Security Analysis Report ---")
        failed_logins = defaultdict(list)

        for event in events:
            if event.event_type == "LOGIN_FAILURE":
                failed_logins[event.source_ip].append(event.timestamp)

        alerts_found = False
        for ip, timestamps in failed_logins.items():
            if len(timestamps) >= self.FAILED_LOGIN_THRESHOLD:
                timestamps.sort()
                # Check for a sequence of failures within the time window
                for i in range(len(timestamps) - self.FAILED_LOGIN_THRESHOLD + 1):
                    window = timestamps[i:i + self.FAILED_LOGIN_THRESHOLD]
                    if window[-1] - window[0] <= self.TIME_WINDOW_SECONDS:
                        print(
                            f"ALERT: Potential brute-force attack detected from IP: {ip}. "
                            f"{self.FAILED_LOGIN_THRESHOLD} failed attempts within "
                            f"{self.TIME_WINDOW_SECONDS} seconds."
                        )
                        alerts_found = True
                        break  # One alert per IP is sufficient
        
        if not alerts_found:
            print("No suspicious activity detected.")
        print("------------------------------\n")

# Main execution block with test cases
def main():
    logger = SecurityLogger()
    monitor = SecurityMonitor()

    # --- Test Case 1: Normal Operations ---
    print(">>> Running Test Case 1: Normal Operations")
    logger.log_event("LOGIN_SUCCESS", "alice", "192.168.1.10", "User alice logged in successfully.")
    time.sleep(1)
    logger.log_event("FILE_ACCESS", "alice", "192.168.1.10", "User alice accessed /data/report.docx.")
    time.sleep(1)
    logger.log_event("LOGOUT", "alice", "192.168.1.10", "User alice logged out.")
    logger.print_logs()
    monitor.analyze_logs(logger.get_event_log())

    # --- Test Case 2: Brute-Force Attack ---
    print(">>> Running Test Case 2: Brute-Force Attack")
    logger.log_event("LOGIN_FAILURE", "admin", "203.0.113.55", "Failed login attempt for user admin.")
    time.sleep(0.5)
    logger.log_event("LOGIN_FAILURE", "root", "203.0.113.55", "Failed login attempt for user root.")
    time.sleep(0.5)
    logger.log_event("LOGIN_FAILURE", "admin", "203.0.113.55", "Failed login attempt for user admin.")
    time.sleep(0.5)
    logger.log_event("LOGIN_FAILURE", "guest", "203.0.113.55", "Failed login attempt for user guest.")
    logger.print_logs()
    monitor.analyze_logs(logger.get_event_log())

    # --- Test Case 3: Distributed Attack (should not trigger alert) ---
    print(">>> Running Test Case 3: Distributed Low-and-Slow Attack")
    logger.log_event("LOGIN_FAILURE", "user", "198.51.100.1", "Failed login.")
    time.sleep(2)
    logger.log_event("LOGIN_FAILURE", "user", "198.51.100.2", "Failed login.")
    time.sleep(2)
    logger.log_event("LOGIN_FAILURE", "user", "198.51.100.3", "Failed login.")
    logger.print_logs()
    monitor.analyze_logs(logger.get_event_log())

    # --- Test Case 4: Mixed Activity & Successful Intrusion ---
    print(">>> Running Test Case 4: Mixed Activity & Eventual Success")
    logger.log_event("LOGIN_FAILURE", "bob", "10.0.0.42", "Failed login: invalid password.")
    time.sleep(1)
    logger.log_event("LOGIN_FAILURE", "bob", "10.0.0.42", "Failed login: invalid password.")
    time.sleep(1)
    logger.log_event("LOGIN_SUCCESS", "bob", "10.0.0.42", "User bob logged in successfully.")
    logger.print_logs()
    monitor.analyze_logs(logger.get_event_log())
    
    # --- Test Case 5: Permission Escalation Attempt ---
    print(">>> Running Test Case 5: Permission Escalation Attempt")
    logger.log_event("LOGIN_SUCCESS", "charlie", "172.16.0.12", "User charlie logged in successfully.")
    time.sleep(1)
    logger.log_event("PERMISSION_DENIED", "charlie", "172.16.0.12", "Access denied for /etc/shadow.")
    logger.print_logs()
    monitor.analyze_logs(logger.get_event_log())

if __name__ == "__main__":
    main()