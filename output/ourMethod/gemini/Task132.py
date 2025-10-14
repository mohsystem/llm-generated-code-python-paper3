import sys
import os
from enum import Enum
from datetime import datetime, timezone

# fcntl is not available on Windows, so file locking will not work.
# This code is intended for POSIX-compliant systems (Linux, macOS).
if sys.platform != "win32":
    import fcntl
else:
    # Mock fcntl for Windows to allow the script to run without error,
    # though without providing any locking functionality.
    class fcntl:
        LOCK_EX = 0
        LOCK_SH = 0
        LOCK_UN = 0
        def flock(self, fd, op):
            pass

LOG_FILE_NAME = "security_events.log"
MAX_DESCRIPTION_LENGTH = 256

class Severity(Enum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"

def sanitize_input(text: str) -> str:
    """Removes newline characters from a string to prevent log injection."""
    return text.replace("\n", "_").replace("\r", "_")

def log_event(event_type: str, severity: Severity, description: str) -> bool:
    """
    Logs a security event to a file with proper locking and sanitization.

    Args:
        event_type: A short string identifying the type of event.
        severity: The severity level of the event.
        description: A detailed description of the event.

    Returns:
        True if logging was successful, False otherwise.
    """
    # 1. Input validation
    if not all([event_type, isinstance(severity, Severity), description]):
        print("Error: Event details cannot be null or empty.", file=sys.stderr)
        return False
    if len(description) > MAX_DESCRIPTION_LENGTH:
        print(f"Error: Description exceeds maximum length of {MAX_DESCRIPTION_LENGTH}", file=sys.stderr)
        return False

    # 2. Sanitize inputs
    sanitized_event_type = sanitize_input(event_type)
    sanitized_description = sanitize_input(description)

    # 3. Create log entry
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = f"[{timestamp}] [{severity.value}] [{sanitized_event_type}]: {sanitized_description}\n"

    # 4. Write to file with an exclusive lock
    try:
        with open(LOG_FILE_NAME, "a", encoding="utf-8") as f:
            if sys.platform != "win32":
                fcntl.flock(f, fcntl.LOCK_EX)
            f.write(log_entry)
            f.flush()
            if sys.platform != "win32":
                fcntl.flock(f, fcntl.LOCK_UN)
    except IOError as e:
        print(f"Failed to write to log file: {e}", file=sys.stderr)
        return False
    return True

def read_logs() -> list[str]:
    """
    Reads all logged events from the security log file.

    Returns:
        A list of log entries as strings, or an empty list on failure.
    """
    if not os.path.exists(LOG_FILE_NAME):
        return []
    
    try:
        with open(LOG_FILE_NAME, "r", encoding="utf-8") as f:
            if sys.platform != "win32":
                fcntl.flock(f, fcntl.LOCK_SH)
            lines = f.readlines()
            if sys.platform != "win32":
                fcntl.flock(f, fcntl.LOCK_UN)
            return [line.strip() for line in lines]
    except IOError as e:
        print(f"Failed to read log file: {e}", file=sys.stderr)
        return []

def main():
    """Main function with test cases."""
    # Clean up previous log file for a fresh run
    if os.path.exists(LOG_FILE_NAME):
        os.remove(LOG_FILE_NAME)

    print("--- Running Security Logger Test Cases ---")

    # Test Case 1: Successful login event
    print("\n1. Logging a successful login event...")
    log_event("LOGIN_SUCCESS", Severity.INFO, "User 'admin' logged in from 192.168.1.1")

    # Test Case 2: Failed login attempt
    print("\n2. Logging a failed login attempt...")
    log_event("LOGIN_FAILURE", Severity.WARN, "Failed login for user 'guest' from 10.0.0.5")

    # Test Case 3: Critical system event
    print("\n3. Logging a critical event...")
    log_event("CONFIG_MODIFIED", Severity.CRITICAL, "Critical system file '/etc/shadow' was modified.")

    # Test Case 4: Attempted log injection
    print("\n4. Logging an event with newline characters (should be sanitized)...")
    log_event("INPUT_VALIDATION_FAIL", Severity.WARN, "User input contained malicious payload:\n<script>alert(1)</script>")

    # Test Case 5: Event description too long
    print("\n5. Logging an event with a description that is too long (should fail)...")
    long_description = "B" * (MAX_DESCRIPTION_LENGTH + 1)
    log_event("DATA_OVERFLOW", Severity.WARN, long_description)

    # Read and display all logs
    print("\n--- Current Security Logs ---")
    logs = read_logs()
    if not logs:
        print("No logs found or unable to read log file.")
    else:
        for log in logs:
            print(log)
    print("--- End of Logs ---")


if __name__ == "__main__":
    main()