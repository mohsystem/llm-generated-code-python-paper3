
class Task114:
    
    @staticmethod
    def copy_string(source):
        """Copy string safely"""
        if source is None:
            return None
        return str(source)
    
    @staticmethod
    def concatenate_strings(str1, str2):
        """Concatenate strings safely with validation"""
        if str1 is None and str2 is None:
            return ""
        if str1 is None:
            return str2
        if str2 is None:
            return str1
        
        # Using join for safe concatenation
        return ''.join([str1, str2])
    
    @staticmethod
    def reverse_string(input_str):
        """Reverse string safely"""
        if input_str is None or len(input_str) == 0:
            return input_str
        
        return input_str[::-1]
    
    @staticmethod
    def to_upper_case_safe(input_str):
        """Convert to uppercase safely"""
        if input_str is None:
            return None
        return input_str.upper()
    
    @staticmethod
    def to_lower_case_safe(input_str):
        """Convert to lowercase safely"""
        if input_str is None:
            return None
        return input_str.lower()
    
    @staticmethod
    def get_substring_safe(input_str, start, end):
        """Get substring with bounds checking"""
        if input_str is None:
            return None
        if start < 0 or end > len(input_str) or start > end:
            raise ValueError("Invalid substring indices")
        return input_str[start:end]
    
    @staticmethod
    def replace_substring(input_str, target, replacement):
        """Replace substring safely"""
        if input_str is None or target is None or replacement is None:
            return input_str
        if len(target) == 0:
            return input_str
        return input_str.replace(target, replacement)


def main():
    print("=== String Operations Test Cases ===\\n")
    
    # Test Case 1: Copy String
    print("Test Case 1 - Copy String:")
    original = "Hello, World!"
    copied = Task114.copy_string(original)
    print(f"Original: {original}")
    print(f"Copied: {copied}")
    print()
    
    # Test Case 2: Concatenate Strings
    print("Test Case 2 - Concatenate Strings:")
    str1 = "Hello"
    str2 = " Python"
    concatenated = Task114.concatenate_strings(str1, str2)
    print(f"String 1: {str1}")
    print(f"String 2: {str2}")
    print(f"Concatenated: {concatenated}")
    print()
    
    # Test Case 3: Reverse String
    print("Test Case 3 - Reverse String:")
    to_reverse = "Programming"
    reversed_str = Task114.reverse_string(to_reverse)
    print(f"Original: {to_reverse}")
    print(f"Reversed: {reversed_str}")
    print()
    
    # Test Case 4: Case Conversion
    print("Test Case 4 - Case Conversion:")
    mixed_case = "HeLLo WoRLd"
    upper = Task114.to_upper_case_safe(mixed_case)
    lower = Task114.to_lower_case_safe(mixed_case)
    print(f"Original: {mixed_case}")
    print(f"Uppercase: {upper}")
    print(f"Lowercase: {lower}")
    print()
    
    # Test Case 5: Substring and Replace
    print("Test Case 5 - Substring and Replace:")
    text = "The quick brown fox jumps over the lazy dog"
    substring = Task114.get_substring_safe(text, 4, 9)
    replaced = Task114.replace_substring(text, "fox", "cat")
    print(f"Original: {text}")
    print(f"Substring (4-9): {substring}")
    print(f"Replaced 'fox' with 'cat': {replaced}")


if __name__ == "__main__":
    main()
