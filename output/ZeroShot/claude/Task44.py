
import re

MAX_INPUT_LENGTH = 1000
ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9\\s.,!?\\-]+$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$')
NUMERIC_PATTERN = re.compile(r'^-?\\d+$')

def validate_and_sanitize_text(input_str):
    if input_str is None:
        return "Error: Input is null"
    
    if not input_str:
        return "Error: Input is empty"
    
    if len(input_str) > MAX_INPUT_LENGTH:
        return f"Error: Input exceeds maximum length of {MAX_INPUT_LENGTH}"
    
    trimmed = input_str.strip()
    
    if not ALPHANUMERIC_PATTERN.match(trimmed):
        return "Error: Input contains invalid characters"
    
    sanitized = (trimmed.replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;")
                       .replace('"', "&quot;")
                       .replace("'", "&#x27;"))
    
    return f"Valid text: {sanitized}"

def validate_email(email):
    if email is None or not email:
        return "Error: Email is null or empty"
    
    if len(email) > 254:
        return "Error: Email exceeds maximum length"
    
    if not EMAIL_PATTERN.match(email):
        return "Error: Invalid email format"
    
    return f"Valid email: {email}"

def validate_and_process_number(input_str):
    if input_str is None or not input_str:
        return "Error: Number input is null or empty"
    
    if not NUMERIC_PATTERN.match(input_str):
        return "Error: Invalid number format"
    
    try:
        number = int(input_str)
        squared = number * number
        return f"Number: {number}, Squared: {squared}"
    except (ValueError, OverflowError):
        return "Error: Number out of range"

def process_operation(operation_type, input_str):
    if operation_type is None or input_str is None:
        return "Error: Operation type or input is null"
    
    op_type = operation_type.lower()
    
    if op_type == "text":
        return validate_and_sanitize_text(input_str)
    elif op_type == "email":
        return validate_email(input_str)
    elif op_type == "number":
        return validate_and_process_number(input_str)
    else:
        return "Error: Unknown operation type"

if __name__ == "__main__":
    print("=== Test Case 1: Valid Text ===")
    result1 = process_operation("text", "Hello World 123!")
    print(result1)
    
    print("\\n=== Test Case 2: Invalid Text with Special Characters ===")
    result2 = process_operation("text", "<script>alert('XSS')</script>")
    print(result2)
    
    print("\\n=== Test Case 3: Valid Email ===")
    result3 = process_operation("email", "user@example.com")
    print(result3)
    
    print("\\n=== Test Case 4: Valid Number ===")
    result4 = process_operation("number", "42")
    print(result4)
    
    print("\\n=== Test Case 5: Invalid Number ===")
    result5 = process_operation("number", "abc123")
    print(result5)
