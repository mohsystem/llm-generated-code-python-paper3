
import re

def is_valid_email(email):
    if not email or not isinstance(email, str):
        return False
    
    # Email regex pattern
    email_regex = r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$'
    
    return bool(re.match(email_regex, email))

def main():
    # Test cases
    test_emails = [
        "user@example.com",
        "john.doe@company.co.uk",
        "invalid.email@",
        "@invalid.com",
        "valid_email123@test-domain.org"
    ]
    
    print("Email Validation Results:")
    for email in test_emails:
        result = "Valid" if is_valid_email(email) else "Invalid"
        print(f"{email} -> {result}")

if __name__ == "__main__":
    main()
