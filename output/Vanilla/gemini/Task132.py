import datetime

class SecurityEvent:
    """Represents a single security event."""
    def __init__(self, event_type, severity, description):
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.event_type = event_type
        self.severity = severity
        self.description = description

    def __str__(self):
        return f"[{self.timestamp}] [{self.severity}] [{self.event_type}] {self.description}"

class SecurityLogger:
    """Manages logging and monitoring of security events."""
    def __init__(self):
        self.event_log = []

    def log_event(self, event_type, severity, description):
        """
        Creates and logs a new security event.
        :param event_type: The type of the event (e.g., "LOGIN", "FILE_ACCESS").
        :param severity: The severity level (e.g., "INFO", "WARNING", "CRITICAL").
        :param description: A detailed description of the event.
        """
        new_event = SecurityEvent(event_type, severity, description)
        self.event_log.append(new_event)
        # In a real system, this might also write to a file or a remote logging service.
        print(f"Logged: {new_event}")
        return new_event # Optional: return the created event

    def display_logs(self):
        """Displays all the logged events to the console."""
        print("\n--- Security Event Log ---")
        if not self.event_log:
            print("No events logged.")
        else:
            for event in self.event_log:
                print(event)
        print("--------------------------\n")

def main():
    """Main function to run test cases."""
    logger = SecurityLogger()

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful login
    logger.log_event("LOGIN_SUCCESS", "INFO", "User 'admin' logged in successfully from IP 192.168.1.10")

    # Test Case 2: Failed login attempt
    logger.log_event("LOGIN_FAILURE", "WARNING", "Failed login attempt for user 'root' from IP 10.0.0.5")

    # Test Case 3: Unauthorized access attempt
    logger.log_event("UNAUTHORIZED_ACCESS", "CRITICAL", "Attempt to access '/etc/shadow' by user 'guest'")

    # Test Case 4: File modification
    logger.log_event("FILE_MODIFICATION", "INFO", "User 'dev' modified '/var/www/index.html'")

    # Test Case 5: Firewall rule change
    logger.log_event("FIREWALL_UPDATE", "WARNING", "Firewall rule added to block port 8080")

    # Display all logged events at the end
    logger.display_logs()

if __name__ == "__main__":
    main()