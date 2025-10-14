import re

def process_user_input(name, age):
    """
    Validates user input and returns a greeting message.
    :param name: The user's name. Must be 2-50 chars, letters and spaces only.
    :param age: The user's age. Must be an integer between 0 and 120.
    :return: A greeting string if the input is valid.
    :raises ValueError: if the input is invalid.
    """
    # Validate name
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Name cannot be empty.")
    
    trimmed_name = name.strip()
    
    if not (2 <= len(trimmed_name) <= 50):
        raise ValueError("Name must be between 2 and 50 characters.")
    
    # Regex to allow only letters and spaces
    if not re.match(r"^[a-zA-Z\s]+$", trimmed_name):
        raise ValueError("Name can only contain letters and spaces.")
        
    # Validate age
    if not isinstance(age, int):
        raise ValueError("Age must be an integer.")
        
    if not (0 <= age <= 120):
        raise ValueError("Age must be between 0 and 120.")
        
    return f"Hello, {trimmed_name}! You are {age} years old."

def main():
    """ Main function with test cases """
    print("--- Running Test Cases ---")
    
    test_cases = [
        ("Test Case 1 (Valid)", "Alice Smith", 30, True),
        ("Test Case 2 (Invalid Name)", "Bob123", 40, False),
        ("Test Case 3 (Invalid Age)", "Charlie Brown", 150, False),
        ("Test Case 4 (Empty Name)", "  ", 25, False),
        ("Test Case 5 (Special Chars)", "Eve <script>", 22, False)
    ]
    
    for description, name, age, should_pass in test_cases:
        try:
            result = process_user_input(name, age)
            if should_pass:
                print(f"{description}: PASSED - {result}")
            else:
                print(f"{description}: FAILED - Did not raise an exception.")
        except ValueError as e:
            if not should_pass:
                print(f"{description}: PASSED - {e}")
            else:
                print(f"{description}: FAILED - {e}")
                
    print("--- Test Cases Finished ---")


if __name__ == "__main__":
    main()