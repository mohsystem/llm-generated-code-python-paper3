import random
import string

def generate_random_number(min_val, max_val):
    """
    Generates a random integer within a specified range (inclusive).
    
    :param min_val: The minimum value of the range.
    :param max_val: The maximum value of the range.
    :return: A random integer between min_val and max_val.
    """
    if min_val > max_val:
        raise ValueError("min_val must not be greater than max_val")
    return random.randint(min_val, max_val)

def generate_random_token(length):
    """
    Generates a random alphanumeric token of a specified length.
    
    :param length: The desired length of the token.
    :return: A random alphanumeric token.
    """
    if length <= 0:
        return ""
    token_characters = string.ascii_letters + string.digits
    return ''.join(random.choice(token_characters) for _ in range(length))

if __name__ == "__main__":
    print("--- Python Random Number and Token Generation ---")

    # Test cases for random number generation
    print("\n--- Random Numbers ---")
    print(f"1. Random number between 1 and 100: {generate_random_number(1, 100)}")
    print(f"2. Random number between -50 and 50: {generate_random_number(-50, 50)}")
    print(f"3. Random number between 1000 and 2000: {generate_random_number(1000, 2000)}")
    print(f"4. Random number between 0 and 1: {generate_random_number(0, 1)}")
    print(f"5. Random number between 5 and 5: {generate_random_number(5, 5)}")

    # Test cases for random token generation
    print("\n--- Random Tokens ---")
    print(f"1. Token of length 8: {generate_random_token(8)}")
    print(f"2. Token of length 12: {generate_random_token(12)}")
    print(f"3. Token of length 16: {generate_random_token(16)}")
    print(f"4. Token of length 1: {generate_random_token(1)}")
    print(f"5. Token of length 32: {generate_random_token(32)}")