
def copy_string(source):
    """String copy operation"""
    if source is None:
        return None
    return str(source)

def concatenate_strings(str1, str2):
    """String concatenation operation"""
    if str1 is None and str2 is None:
        return ""
    if str1 is None:
        return str2
    if str2 is None:
        return str1
    return str1 + str2

def reverse_string(input_str):
    """String reverse operation"""
    if input_str is None or len(input_str) == 0:
        return input_str
    return input_str[::-1]

def to_upper_case_string(input_str):
    """String uppercase operation"""
    if input_str is None:
        return None
    return input_str.upper()

def to_lower_case_string(input_str):
    """String lowercase operation"""
    if input_str is None:
        return None
    return input_str.lower()

def get_substring(input_str, start, end):
    """String substring operation"""
    if input_str is None or start < 0 or end > len(input_str) or start > end:
        return ""
    return input_str[start:end]

def replace_string(input_str, target, replacement):
    """String replace operation"""
    if input_str is None or target is None or replacement is None:
        return input_str
    return input_str.replace(target, replacement)

def get_string_length(input_str):
    """String length operation"""
    if input_str is None:
        return 0
    return len(input_str)

if __name__ == "__main__":
    # Test Case 1: Copy string
    print("Test Case 1 - Copy String:")
    original = "Hello World"
    copied = copy_string(original)
    print(f"Original: {original}")
    print(f"Copied: {copied}")
    print()
    
    # Test Case 2: Concatenate strings
    print("Test Case 2 - Concatenate Strings:")
    str1 = "Hello"
    str2 = " World"
    concatenated = concatenate_strings(str1, str2)
    print(f"String 1: {str1}")
    print(f"String 2: {str2}")
    print(f"Concatenated: {concatenated}")
    print()
    
    # Test Case 3: Reverse string
    print("Test Case 3 - Reverse String:")
    text = "Programming"
    reversed_text = reverse_string(text)
    print(f"Original: {text}")
    print(f"Reversed: {reversed_text}")
    print()
    
    # Test Case 4: Case conversion and substring
    print("Test Case 4 - Case Conversion and Substring:")
    message = "Secure Coding Practice"
    print(f"Original: {message}")
    print(f"Uppercase: {to_upper_case_string(message)}")
    print(f"Lowercase: {to_lower_case_string(message)}")
    print(f"Substring (0-6): {get_substring(message, 0, 6)}")
    print()
    
    # Test Case 5: Replace and length
    print("Test Case 5 - Replace and Length:")
    sentence = "Java is great. Java is powerful."
    replaced = replace_string(sentence, "Java", "Python")
    print(f"Original: {sentence}")
    print(f"Replaced: {replaced}")
    print(f"Original Length: {get_string_length(sentence)}")
    print(f"Replaced Length: {get_string_length(replaced)}")
