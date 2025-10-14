import secrets
import string

def generate_random_string(length: int) -> str:
    """
    Generates an unpredictable random string of a specified length using only ASCII letters.
    This function uses the 'secrets' module, which is designed for generating
    cryptographically strong random numbers suitable for managing secrets.

    Args:
        length: The desired length of the string.

    Returns:
        A random string of the specified length, or an empty string if length is <= 0.
    """
    if length <= 0:
        return ""
    
    # string.ascii_letters contains 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    print("\nPython Test Cases:")
    
    # Test Case 1: Standard length
    len1 = 16
    random_str1 = generate_random_string(len1)
    print(f"1. Length {len1}: {random_str1} (Actual length: {len(random_str1)})")

    # Test Case 2: Short length
    len2 = 5
    random_str2 = generate_random_string(len2)
    print(f"2. Length {len2}: {random_str2} (Actual length: {len(random_str2)})")

    # Test Case 3: Long length
    len3 = 64
    random_str3 = generate_random_string(len3)
    print(f"3. Length {len3}: {random_str3} (Actual length: {len(random_str3)})")
    
    # Test Case 4: Zero length
    len4 = 0
    random_str4 = generate_random_string(len4)
    print(f"4. Length {len4}: \"{random_str4}\" (Actual length: {len(random_str4)})")

    # Test Case 5: Negative length
    len5 = -10
    random_str5 = generate_random_string(len5)
    print(f"5. Length {len5}: \"{random_str5}\" (Actual length: {len(random_str5)})")