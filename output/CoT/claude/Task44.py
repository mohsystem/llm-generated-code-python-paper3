
import re

class Task44:
    MAX_INPUT_LENGTH = 100
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9\\s]+$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')
    NUMERIC_PATTERN = re.compile(r'^\\d+$')
    
    @staticmethod
    def sanitize_input(input_str):
        """Sanitize user input to prevent injection attacks"""
        if input_str is None:
            return ""
        
        # Trim whitespace
        input_str = input_str.strip()
        
        # Check length
        if len(input_str) > Task44.MAX_INPUT_LENGTH:
            raise ValueError(f"Input exceeds maximum length of {Task44.MAX_INPUT_LENGTH}")
        
        # Remove potential SQL injection characters
        input_str = re.sub(r"[;'\"\\]", "", input_str)
        
        # Remove potential XSS characters
        input_str = re.sub(r"[<>]", "", input_str)
        
        return input_str
    
    @staticmethod
    def validate_alphanumeric(input_str):
        """Validate alphanumeric input"""
        if not input_str:
            return False
        return bool(Task44.ALPHANUMERIC_PATTERN.match(input_str))
    
    @staticmethod
    def validate_email(input_str):
        """Validate email format"""
        if not input_str:
            return False
        return bool(Task44.EMAIL_PATTERN.match(input_str)) and len(input_str) <= Task44.MAX_INPUT_LENGTH
    
    @staticmethod
    def validate_numeric(input_str):
        """Validate numeric input"""
        if not input_str:
            return False
        return bool(Task44.NUMERIC_PATTERN.match(input_str))
    
    @staticmethod
    def safe_parse_int(input_str, default_value=0):
        """Safely parse integer with bounds checking"""
        try:
            if not Task44.validate_numeric(input_str):
                return default_value
            value = int(input_str)
            if value > 2147483647 or value < -2147483648:
                return default_value
            return value
        except (ValueError, OverflowError):
            return default_value
    
    @staticmethod
    def process_input(input_str, input_type):
        """Process and validate user input based on type"""
        if input_str is None or input_type is None:
            return "Error: Null input provided"
        
        try:
            sanitized = Task44.sanitize_input(input_str)
            
            input_type_lower = input_type.lower()
            
            if input_type_lower == "alphanumeric":
                if Task44.validate_alphanumeric(sanitized):
                    return f"Valid alphanumeric input: {sanitized}"
                else:
                    return "Invalid alphanumeric input"
            
            elif input_type_lower == "email":
                if Task44.validate_email(sanitized):
                    return f"Valid email: {sanitized}"
                else:
                    return "Invalid email format"
            
            elif input_type_lower == "numeric":
                if Task44.validate_numeric(sanitized):
                    number = Task44.safe_parse_int(sanitized, 0)
                    return f"Valid number: {number}, Doubled: {number * 2}"
                else:
                    return "Invalid numeric input"
            
            else:
                return "Unknown input type"
                
        except ValueError as e:
            return f"Error: {str(e)}"


def main():
    print("=== Secure Input Validation Test Cases ===\\n")
    
    # Test Case 1: Valid alphanumeric input
    print("Test 1 - Valid Alphanumeric:")
    print(Task44.process_input("Hello World 123", "alphanumeric"))
    print()
    
    # Test Case 2: Valid email
    print("Test 2 - Valid Email:")
    print(Task44.process_input("user@example.com", "email"))
    print()
    
    # Test Case 3: Valid numeric input
    print("Test 3 - Valid Numeric:")
    print(Task44.process_input("42", "numeric"))
    print()
    
    # Test Case 4: SQL Injection attempt
    print("Test 4 - SQL Injection Attempt:")
    print(Task44.process_input("admin' OR '1'='1", "alphanumeric"))
    print()
    
    # Test Case 5: XSS attempt
    print("Test 5 - XSS Attempt:")
    print(Task44.process_input("<script>alert('XSS')</script>", "alphanumeric"))
    print()


if __name__ == "__main__":
    main()
