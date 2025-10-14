
import random
import math

class Task106:
    class RSA:
        def __init__(self, bit_length=512):
            self.bit_length = bit_length
            p = self._generate_prime(bit_length // 2)
            q = self._generate_prime(bit_length // 2)
            
            self.n = p * q
            phi = (p - 1) * (q - 1)
            
            self.e = 65537
            while math.gcd(self.e, phi) != 1:
                self.e += 2
            
            self.d = self._mod_inverse(self.e, phi)
        
        def _generate_prime(self, bits):
            while True:
                num = random.getrandbits(bits)
                num |= (1 << bits - 1) | 1
                if self._is_prime(num):
                    return num
        
        def _is_prime(self, n, k=5):
            if n < 2:
                return False
            if n == 2 or n == 3:
                return True
            if n % 2 == 0:
                return False
            
            r, d = 0, n - 1
            while d % 2 == 0:
                r += 1
                d //= 2
            
            for _ in range(k):
                a = random.randrange(2, n - 1)
                x = pow(a, d, n)
                
                if x == 1 or x == n - 1:
                    continue
                
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True
        
        def _mod_inverse(self, a, m):
            def extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y
            
            _, x, _ = extended_gcd(a, m)
            return (x % m + m) % m
        
        def encrypt(self, message):
            return pow(message, self.e, self.n)
        
        def decrypt(self, encrypted):
            return pow(encrypted, self.d, self.n)
        
        def encrypt_string(self, message):
            msg_int = int.from_bytes(message.encode(), 'big')
            encrypted = self.encrypt(msg_int)
            return str(encrypted)
        
        def decrypt_string(self, encrypted_message):
            encrypted_int = int(encrypted_message)
            decrypted_int = self.decrypt(encrypted_int)
            byte_length = (decrypted_int.bit_length() + 7) // 8
            return decrypted_int.to_bytes(byte_length, 'big').decode()

def main():
    print("RSA Encryption/Decryption Test Cases:")
    print("=====================================\\n")
    
    # Test Case 1
    print("Test Case 1: Simple message")
    rsa1 = Task106.RSA(512)
    message1 = "Hello"
    encrypted1 = rsa1.encrypt_string(message1)
    decrypted1 = rsa1.decrypt_string(encrypted1)
    print(f"Original: {message1}")
    print(f"Encrypted: {encrypted1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {message1 == decrypted1}\\n")
    
    # Test Case 2
    print("Test Case 2: Longer message")
    rsa2 = Task106.RSA(512)
    message2 = "RSA Algorithm"
    encrypted2 = rsa2.encrypt_string(message2)
    decrypted2 = rsa2.decrypt_string(encrypted2)
    print(f"Original: {message2}")
    print(f"Encrypted: {encrypted2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Match: {message2 == decrypted2}\\n")
    
    # Test Case 3
    print("Test Case 3: Numbers")
    rsa3 = Task106.RSA(512)
    message3 = "12345"
    encrypted3 = rsa3.encrypt_string(message3)
    decrypted3 = rsa3.decrypt_string(encrypted3)
    print(f"Original: {message3}")
    print(f"Encrypted: {encrypted3}")
    print(f"Decrypted: {decrypted3}")
    print(f"Match: {message3 == decrypted3}\\n")
    
    # Test Case 4
    print("Test Case 4: Special characters")
    rsa4 = Task106.RSA(512)
    message4 = "Test@123!"
    encrypted4 = rsa4.encrypt_string(message4)
    decrypted4 = rsa4.decrypt_string(encrypted4)
    print(f"Original: {message4}")
    print(f"Encrypted: {encrypted4}")
    print(f"Decrypted: {decrypted4}")
    print(f"Match: {message4 == decrypted4}\\n")
    
    # Test Case 5
    print("Test Case 5: Single character")
    rsa5 = Task106.RSA(512)
    message5 = "A"
    encrypted5 = rsa5.encrypt_string(message5)
    decrypted5 = rsa5.decrypt_string(encrypted5)
    print(f"Original: {message5}")
    print(f"Encrypted: {encrypted5}")
    print(f"Decrypted: {decrypted5}")
    print(f"Match: {message5 == decrypted5}\\n")

if __name__ == "__main__":
    main()
