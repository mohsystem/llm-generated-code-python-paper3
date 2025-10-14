
import random
import math

class Task106:
    def __init__(self, bit_length=512):
        self.bit_length = bit_length
        self.e = 65537
        p = self.generate_prime(bit_length // 2)
        q = self.generate_prime(bit_length // 2)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.d = self.mod_inverse(self.e, phi)
    
    def is_prime(self, num, k=5):
        if num < 2:
            return False
        if num == 2 or num == 3:
            return True
        if num % 2 == 0:
            return False
        
        r, d = 0, num - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, num - 1)
            x = pow(a, d, num)
            if x == 1 or x == num - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, num)
                if x == num - 1:
                    break
            else:
                return False
        return True
    
    def generate_prime(self, bit_length):
        while True:
            num = random.getrandbits(bit_length)
            num |= (1 << bit_length - 1) | 1
            if self.is_prime(num):
                return num
    
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m):
        if self.gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m
    
    def encrypt(self, message):
        return pow(message, self.e, self.n)
    
    def decrypt(self, encrypted):
        return pow(encrypted, self.d, self.n)
    
    def encrypt_string(self, message):
        message_bytes = message.encode()
        message_int = int.from_bytes(message_bytes, byteorder='big')
        encrypted = self.encrypt(message_int)
        return str(encrypted)
    
    def decrypt_string(self, encrypted):
        encrypted_int = int(encrypted)
        decrypted_int = self.decrypt(encrypted_int)
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
        return decrypted_bytes.decode()

if __name__ == "__main__":
    print("RSA Encryption/Decryption Test Cases:\\n")
    
    # Test Case 1
    print("Test Case 1:")
    rsa1 = Task106()
    msg1 = "Hello"
    encrypted1 = rsa1.encrypt_string(msg1)
    decrypted1 = rsa1.decrypt_string(encrypted1)
    print(f"Original: {msg1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {msg1 == decrypted1}\\n")
    
    # Test Case 2
    print("Test Case 2:")
    rsa2 = Task106()
    msg2 = "RSA Algorithm"
    encrypted2 = rsa2.encrypt_string(msg2)
    decrypted2 = rsa2.decrypt_string(encrypted2)
    print(f"Original: {msg2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Match: {msg2 == decrypted2}\\n")
    
    # Test Case 3
    print("Test Case 3:")
    rsa3 = Task106()
    num3 = 12345
    encrypted3 = rsa3.encrypt(num3)
    decrypted3 = rsa3.decrypt(encrypted3)
    print(f"Original: {num3}")
    print(f"Decrypted: {decrypted3}")
    print(f"Match: {num3 == decrypted3}\\n")
    
    # Test Case 4
    print("Test Case 4:")
    rsa4 = Task106()
    msg4 = "Secure Communication"
    encrypted4 = rsa4.encrypt_string(msg4)
    decrypted4 = rsa4.decrypt_string(encrypted4)
    print(f"Original: {msg4}")
    print(f"Decrypted: {decrypted4}")
    print(f"Match: {msg4 == decrypted4}\\n")
    
    # Test Case 5
    print("Test Case 5:")
    rsa5 = Task106()
    msg5 = "123"
    encrypted5 = rsa5.encrypt_string(msg5)
    decrypted5 = rsa5.decrypt_string(encrypted5)
    print(f"Original: {msg5}")
    print(f"Decrypted: {decrypted5}")
    print(f"Match: {msg5 == decrypted5}\\n")
