import re

def perform_operation(username, age_str):
    """
    Processes user input after validation.
    
    Args:
        username (str): A string representing the username.
        age_str (str): A string representing the user's age.
        
    Returns:
        str: A string with the result of the operation or an error message.
    """
    # 1. Validate Username
    if not username or not username.strip():
        return "Error: Username cannot be empty."
    
    if not 3 <= len(username) <= 20:
        return "Error: Username must be between 3 and 20 characters long."
    
    # Use isalnum() for simple check, or regex for more specific rules
    if not username.isalnum():
        return "Error: Username must contain only alphanumeric characters."

    # 2. Validate Age
    try:
        age = int(age_str)
    except (ValueError, TypeError):
        return "Error: Age must be a valid integer."
        
    if not 0 <= age <= 120:
        return "Error: Age must be between 0 and 120."

    # 3. Perform Operation if all validations pass
    return f"Success: Hello {username}, you are {age} years old."

if __name__ == "__main__":
    # Main block with 5 test cases
    print("--- Running Test Cases ---")

    # Test Case 1: Valid input
    print("Test 1 (Valid):")
    print(perform_operation("Alice", "30"))
    print()

    # Test Case 2: Invalid age (non-numeric)
    print("Test 2 (Invalid Age - Text):")
    print(perform_operation("Bob", "twenty"))
    print()

    # Test Case 3: Invalid age (out of range)
    print("Test 3 (Invalid Age - Range):")
    print(perform_operation("Charlie", "150"))
    print()

    # Test Case 4: Invalid username (special characters)
    print("Test 4 (Invalid Username - Chars):")
    print(perform_operation("David!@", "40"))
    print()
    
    # Test Case 5: Invalid username (too short)
    print("Test 5 (Invalid Username - Length):")
    print(perform_operation("Ed", "25"))
    print()