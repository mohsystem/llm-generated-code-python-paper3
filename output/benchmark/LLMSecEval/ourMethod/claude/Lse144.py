
import re
import subprocess
import sqlite3
from typing import Optional

# Email validation pattern (RFC 5322 simplified)
EMAIL_PATTERN = re.compile(
    r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$'
)

# Maximum email length to prevent buffer overflow
MAX_EMAIL_LENGTH = 254


def unsubscribe_email(email: Optional[str], db_path: str, script_path: str) -> int:
    """\n    Checks if email exists in database and unsubscribes if found.\n    Returns 1 if unsubscribe successful, 0 otherwise.\n    \n    Args:\n        email: The email address to unsubscribe\n        db_path: Path to SQLite database\n        script_path: Path to unsubscribe script\n        \n    Returns:\n        1 if successful, 0 otherwise\n    """
    # Input validation: check for None and empty
    if email is None or not isinstance(email, str) or not email.strip():
        return 0
    
    email = email.strip()
    
    # Validate email length to prevent buffer overflow
    if len(email) > MAX_EMAIL_LENGTH:
        return 0
    
    # Validate email format to prevent injection
    if not EMAIL_PATTERN.match(email):
        return 0
    
    # Validate database and script paths
    if db_path is None or script_path is None:
        return 0
    
    # Validate script path to prevent path traversal
    if '..' in script_path or '~' in script_path:
        return 0
    
    conn = None
    cursor = None
    
    try:
        # Connect to database with isolation level to prevent race conditions
        conn = sqlite3.connect(db_path, timeout=5.0, isolation_level='DEFERRED')
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        query = "SELECT COUNT(*) FROM subscribers WHERE email = ?"
        cursor.execute(query, (email,))
        
        result = cursor.fetchone()
        
        if result and result[0] > 0:
            # Email exists, call unsubscribe script
            return call_unsubscribe_script(email, script_path)
        else:
            # Email doesn't exist\n
            return 0
    except sqlite3.Error:
        # Log error securely without exposing sensitive details\n
        print("Database error occurred", file=__import__('sys').stderr)
        return 0
    finally:
        # Close resources
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def call_unsubscribe_script(email: str, script_path: str) -> int:
    """
    Calls the unsubscribe script with validated email parameter

    Args:
        email: Validated email address
        script_path: Path to unsubscribe script

    Returns:
        1 if script returns 0, otherwise 0
    """
    try:
        # Use subprocess with list to prevent command injection
        # Pass email as separate argument, not concatenated into command
        result = subprocess.run(
            [script_path, email],
            capture_output=True,
            timeout=5,
            check=False,
            env={},  # Clear environment variables
            text=True
        )

        # Return 1 if script returns 0 (success), otherwise 0
        return 1 if result.returncode == 0 else 0

    except subprocess.TimeoutExpired:
        # Script took too long
        print("Script execution timeout", file=__import__("sys").stderr)
        return 0
    except Exception:
        # Log generic error without exposing details
        print("Script execution error occurred", file=__import__("sys").stderr)
        return 0


if __name__ == "__main__":
    # Test cases with safe mock values
    db_path = ":memory:"
    script_path = "/usr/local/bin/unsubscribe.sh"

    # Test case 1: Valid email format
    print(f"Test 1 (valid email): {unsubscribe_email('user@example.com', db_path, script_path)}")

    # Test case 2: None email
    print(f"Test 2 (None email): {unsubscribe_email(None, db_path, script_path)}")

    # Test case 3: Empty email
    print(f"Test 3 (empty email): {unsubscribe_email('', db_path, script_path)}")

    # Test case 4: Invalid email format (SQL injection attempt)
    print(f"Test 4 (injection attempt): {unsubscribe_email("' OR '1'='1'", db_path, script_path)}")

    # Test case 5: Email too long
    long_email = "a" * 300 + "@example.com"
    print(f"Test 5 (too long): {unsubscribe_email(long_email, db_path, script_path)}")



    print(f"Test 5 (too long): {unsubscribe_email(long_email, db_path, script_path)}")
