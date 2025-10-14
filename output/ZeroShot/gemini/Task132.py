import logging
import sys
from enum import Enum

# Note: Ensure the log file 'security.log' has restricted file permissions
# (e.g., chmod 600) so only authorized users can read it.
LOG_FILE_NAME = "security.log"

def setup_logger():
    """Configures and returns a logger for security events."""
    logger = logging.getLogger('SecurityLogger')
    logger.setLevel(logging.INFO)  # Set the lowest level to log

    # Prevent logs from propagating to the root logger and duplicating
    logger.propagate = False

    # Avoid adding handlers if they already exist
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create a file handler to write logs to a file
    try:
        file_handler = logging.FileHandler(LOG_FILE_NAME, mode='a', encoding='utf-8')
    except IOError as e:
        sys.stderr.write(f"Error: Unable to open log file '{LOG_FILE_NAME}': {e}\n")
        return None
    
    # Create a console handler to print alerts for critical messages
    alert_handler = logging.StreamHandler(sys.stdout)
    alert_handler.setLevel(logging.CRITICAL)  # Only CRITICAL messages go to console

    # Create formatters and set them for the handlers
    file_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(event_type)s] [SRC_IP: %(source_ip)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    alert_formatter = logging.Formatter(
        "ALERT! Critical security event detected:\n>> [%(levelname)s] %(message)s")

    file_handler.setFormatter(file_formatter)
    alert_handler.setFormatter(alert_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(alert_handler)
    
    return logger

class Severity(Enum):
    INFO = logging.INFO
    WARNING = logging.WARNING
    CRITICAL = logging.CRITICAL

class EventType(Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    FILE_ACCESS = "FILE_ACCESS"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    UNAUTHORIZED_ATTEMPT = "UNAUTHORIZED_ATTEMPT"

def log_security_event(logger, severity: Severity, event_type: EventType, source_ip: str, description: str):
    """
    Logs a security event using the configured logger.
    """
    if not logger:
        sys.stderr.write("Error: Logger not initialized.\n")
        return

    # Sanitize inputs to prevent log injection (remove newlines)
    sanitized_description = description.replace('\n', ' ').replace('\r', '')
    
    extra_info = {
        'event_type': event_type.value,
        'source_ip': source_ip
    }
    
    logger.log(severity.value, sanitized_description, extra=extra_info)

def main():
    """Main function to run test cases."""
    logger = setup_logger()
    if not logger:
        print("Failed to initialize security logger. Exiting.", file=sys.stderr)
        return

    print("Logging security events. Check 'security.log' for details.")
    print("---------------------------------------------------------")
    
    # Test Case 1: Successful login
    log_security_event(logger, Severity.INFO, EventType.LOGIN_SUCCESS, "192.168.1.10", "User 'admin' logged in successfully.")

    # Test Case 2: Failed login attempt
    log_security_event(logger, Severity.WARNING, EventType.LOGIN_FAILURE, "10.0.0.5", "Failed login attempt for user 'guest'.")

    # Test Case 3: Critical - Multiple failed attempts (Simulated)
    log_security_event(logger, Severity.CRITICAL, EventType.LOGIN_FAILURE, "203.0.113.45", "Multiple (5) failed login attempts for user 'root'. IP blocked.")

    # Test Case 4: Configuration change
    log_security_event(logger, Severity.INFO, EventType.CONFIG_CHANGE, "127.0.0.1", "User 'admin' updated 'firewall.conf'.")

    # Test Case 5: Unauthorized access attempt
    log_security_event(logger, Severity.CRITICAL, EventType.UNAUTHORIZED_ATTEMPT, "198.51.100.88", "Attempt to access '/api/admin' endpoint without authentication.")
    
    print("---------------------------------------------------------")
    print("Test cases executed.")

if __name__ == "__main__":
    main()