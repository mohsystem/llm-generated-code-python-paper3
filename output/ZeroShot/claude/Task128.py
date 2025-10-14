
import secrets
import string
import base64

class Task128:
    @staticmethod
    def generate_random_int(min_val, max_val):
        """Generate random integer within a range"""
        if min_val >= max_val:
            raise ValueError("Max must be greater than min")
        return secrets.randbelow(max_val - min_val) + min_val
    
    @staticmethod
    def generate_random_long():
        """Generate random long (64-bit integer)"""
        return secrets.randbits(64)
    
    @staticmethod
    def generate_random_token(byte_length):
        """Generate random token (Base64 encoded)"""
        if byte_length <= 0:
            raise ValueError("Byte length must be positive")
        random_bytes = secrets.token_bytes(byte_length)
        return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    
    @staticmethod
    def generate_random_alphanumeric(length):
        """Generate random alphanumeric string"""
        if length <= 0:
            raise ValueError("Length must be positive")
        chars = string.ascii_letters + string.digits
        return ''.join(secrets.choice(chars) for _ in range(length))

def main():
    task = Task128()
    
    print("Test Case 1 - Random Integer (1-100):")
    print(task.generate_random_int(1, 100))
    
    print("\\nTest Case 2 - Random Long:")
    print(task.generate_random_long())
    
    print("\\nTest Case 3 - Random Token (32 bytes):")
    print(task.generate_random_token(32))
    
    print("\\nTest Case 4 - Random Alphanumeric (16 chars):")
    print(task.generate_random_alphanumeric(16))
    
    print("\\nTest Case 5 - Multiple Random Integers:")
    for _ in range(5):
        print(task.generate_random_int(1, 1000))

if __name__ == "__main__":
    main()
