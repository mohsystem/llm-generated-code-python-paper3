
import re

def is_valid_email(email):
    if not email:
        return False
    
    # Regular expression for email validation
    email_regex = r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$'
    
    return re.match(email_regex, email) is not None

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
        print(f"{email} : {result}")

if __name__ == "__main__":
    main()
