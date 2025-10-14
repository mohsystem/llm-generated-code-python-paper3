
import re

class Task55:
    MAX_EMAIL_LENGTH = 320  # RFC 5321
    MAX_LOCAL_LENGTH = 64
    MAX_DOMAIN_LENGTH = 255
    
    @staticmethod
    def is_valid_email(email):
        """Validate email address with security measures."""
        # Input validation - prevent null and length attacks
        if not email or not isinstance(email, str):
            return False
        
        email = email.strip()
        
        # Check maximum length to prevent DoS
        if len(email) > Task55.MAX_EMAIL_LENGTH:
            return False
        
        # Check for exactly one @ symbol
        at_count = email.count('@')
        if at_count != 1:
            return False
        
        at_position = email.index('@')
        if at_position == 0 or at_position == len(email) - 1:
            return False
        
        # Split into local and domain parts
        local_part = email[:at_position]
        domain_part = email[at_position + 1:]
        
        # Validate lengths
        if len(local_part) > Task55.MAX_LOCAL_LENGTH or len(domain_part) > Task55.MAX_DOMAIN_LENGTH:
            return False
        
        # Validate local part - use simple pattern to prevent ReDoS
        local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
        if not re.match(local_pattern, local_part):
            return False
        
        # Check for consecutive dots or leading/trailing dots
        if local_part.startswith('.') or local_part.endswith('.') or '..' in local_part:
            return False
        
        # Validate domain part - use simple pattern to prevent ReDoS
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain_part):
            return False
        
        # Check for valid TLD (at least one dot in domain)
        if '.' not in domain_part:
            return False
        
        # Validate TLD length (2-63 characters)
        domain_parts = domain_part.split('.')
        tld = domain_parts[-1]
        if len(tld) < 2 or len(tld) > 63:
            return False
        
        return True


def main():
    """Test the email validation function."""
    test_emails = [
        "user@example.com",           # Valid
        "test.email@domain.co.uk",    # Valid
        "invalid.email@",             # Invalid - no domain
        "@invalid.com",               # Invalid - no local part
        "no-at-sign.com",             # Invalid - no @ symbol
        "user@domain",                # Invalid - no TLD
        "user..name@domain.com",      # Invalid - consecutive dots
        ".user@domain.com",           # Invalid - starts with dot
        "user@.domain.com",           # Invalid - domain starts with dot
        "a" * 65 + "@test.com"        # Invalid - local part too long
    ]
    
    print("Email Validation Test Results:")
    print("=" * 50)
    for email in test_emails:
        display_email = email if len(email) <= 50 else email[:47] + "..."
        result = "VALID" if Task55.is_valid_email(email) else "INVALID"
        print(f"{display_email:<50} : {result}")


if __name__ == "__main__":
    main()
