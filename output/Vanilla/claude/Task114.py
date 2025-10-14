
class Task114:
    # Copy string
    @staticmethod
    def copy_string(source):
        if source is None:
            return None
        return str(source)
    
    # Concatenate two strings
    @staticmethod
    def concatenate_strings(str1, str2):
        if str1 is None:
            str1 = ""
        if str2 is None:
            str2 = ""
        return str1 + str2
    
    # Reverse a string
    @staticmethod
    def reverse_string(string):
        if string is None:
            return None
        return string[::-1]
    
    # Convert to uppercase
    @staticmethod
    def to_upper_case(string):
        if string is None:
            return None
        return string.upper()
    
    # Convert to lowercase
    @staticmethod
    def to_lower_case(string):
        if string is None:
            return None
        return string.lower()
    
    # Get substring
    @staticmethod
    def get_substring(string, start, end):
        if string is None or start < 0 or end > len(string) or start > end:
            return ""
        return string[start:end]
    
    # Count character occurrences
    @staticmethod
    def count_character(string, ch):
        if string is None:
            return 0
        return string.count(ch)
    
    # Replace character
    @staticmethod
    def replace_character(string, old_char, new_char):
        if string is None:
            return None
        return string.replace(old_char, new_char)
    
    # Find string length
    @staticmethod
    def get_length(string):
        if string is None:
            return 0
        return len(string)
    
    # Check if string is palindrome
    @staticmethod
    def is_palindrome(string):
        if string is None:
            return False
        return string == Task114.reverse_string(string)


if __name__ == "__main__":
    print("=== Test Case 1: Copy and Concatenate ===")
    original = "Hello"
    copied = Task114.copy_string(original)
    print(f"Original: {original}")
    print(f"Copied: {copied}")
    concatenated = Task114.concatenate_strings("Hello", " World")
    print(f"Concatenated: {concatenated}")
    
    print("\\n=== Test Case 2: Reverse String ===")
    str2 = "Programming"
    print(f"Original: {str2}")
    print(f"Reversed: {Task114.reverse_string(str2)}")
    
    print("\\n=== Test Case 3: Case Conversion ===")
    str3 = "Java Python CPP"
    print(f"Original: {str3}")
    print(f"Uppercase: {Task114.to_upper_case(str3)}")
    print(f"Lowercase: {Task114.to_lower_case(str3)}")
    
    print("\\n=== Test Case 4: Substring and Character Operations ===")
    str4 = "Hello World"
    print(f"Original: {str4}")
    print(f"Substring (0, 5): {Task114.get_substring(str4, 0, 5)}")
    print(f"Count 'l': {Task114.count_character(str4, 'l')}")
    print(f"Replace 'o' with '0': {Task114.replace_character(str4, 'o', '0')}")
    print(f"Length: {Task114.get_length(str4)}")
    
    print("\\n=== Test Case 5: Palindrome Check ===")
    str5a = "radar"
    str5b = "hello"
    print(f"{str5a} is palindrome: {Task114.is_palindrome(str5a)}")
    print(f"{str5b} is palindrome: {Task114.is_palindrome(str5b)}")
