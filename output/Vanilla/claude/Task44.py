
import re

class Task44:
    MAX_INPUT_LENGTH = 100
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9\\s]+$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')
    NUMERIC_PATTERN = re.compile(r'^-?\\d+$')

    @staticmethod
    def validate_and_sanitize_input(input_str):
        if input_str is None or len(input_str) == 0:
            return "Error: Input cannot be null or empty"
        
        if len(input_str) > Task44.MAX_INPUT_LENGTH:
            return f"Error: Input exceeds maximum length of {Task44.MAX_INPUT_LENGTH}"
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'();{}\[\]\\]', '', input_str)
        return sanitized.strip()

    @staticmethod
    def validate_alphanumeric(input_str):
        sanitized = Task44.validate_and_sanitize_input(input_str)
        if sanitized.startswith("Error:"):
            return sanitized
        
        if not Task44.ALPHANUMERIC_PATTERN.match(sanitized):
            return "Error: Input must contain only alphanumeric characters and spaces"
        
        return f"Valid alphanumeric: {sanitized}"

    @staticmethod
    def validate_email(input_str):
        sanitized = Task44.validate_and_sanitize_input(input_str)
        if sanitized.startswith("Error:"):
            return sanitized
        
        if not Task44.EMAIL_PATTERN.match(sanitized):
            return "Error: Invalid email format"
        
        return f"Valid email: {sanitized}"

    @staticmethod
    def validate_numeric(input_str):
        sanitized = Task44.validate_and_sanitize_input(input_str)
        if sanitized.startswith("Error:"):
            return sanitized
        
        if not Task44.NUMERIC_PATTERN.match(sanitized):
            return "Error: Input must be a valid number"
        
        return f"Valid number: {sanitized}"

    @staticmethod
    def process_input(input_str, validation_type):
        if validation_type is None or len(validation_type) == 0:
            return "Error: Validation type not specified"
        
        validation_type = validation_type.lower()
        
        if validation_type == "alphanumeric":
            return Task44.validate_alphanumeric(input_str)
        elif validation_type == "email":
            return Task44.validate_email(input_str)
        elif validation_type == "numeric":
            return Task44.validate_numeric(input_str)
        else:
            return "Error: Unknown validation type"


def main():
    print("=== Test Case 1: Valid Alphanumeric ===")
    print(Task44.process_input("Hello World 123", "alphanumeric"))
    
    print("\\n=== Test Case 2: Valid Email ===")
    print(Task44.process_input("user@example.com", "email"))
    
    print("\\n=== Test Case 3: Valid Numeric ===")
    print(Task44.process_input("12345", "numeric"))
    
    print("\\n=== Test Case 4: Invalid Input with Special Characters ===")
    print(Task44.process_input("<script>alert('xss')</script>", "alphanumeric"))
    
    print("\\n=== Test Case 5: Input Too Long ===")
    long_input = "a" * 150
    print(Task44.process_input(long_input, "alphanumeric"))


if __name__ == "__main__":
    main()
