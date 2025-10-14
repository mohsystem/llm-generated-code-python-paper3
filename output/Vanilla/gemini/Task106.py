import math

def gcd(a, b):
    """Computes the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm to find `d`, `x`, `y` such that `d = ax + by`.
    """
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(e, phi):
    """Computes the modular inverse of e mod phi."""
    d, x, y = extended_gcd(e, phi)
    if d != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

def generate_keypair(p, q):
    """
    Generates a public/private key pair.
    p and q must be prime numbers.
    """
    if p == q:
        raise ValueError('p and q cannot be equal')

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 17  # A common choice for e
    while gcd(e, phi) != 1:
        e += 2  # Try next odd number if 17 is not coprime

    # Calculate d, the modular inverse of e
    d = mod_inverse(e, phi)

    # Public key is (e, n), Private key is (d, n)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext_message):
    """
    Encrypts a message using the public key.
    M^e mod n
    """
    e, n = public_key
    cipher_text = pow(plaintext_message, e, n)
    return cipher_text

def decrypt(private_key, ciphertext):
    """
    Decrypts a message using the private key.
    C^d mod n
    """
    d, n = private_key
    plain_text = pow(ciphertext, d, n)
    return plain_text

def main():
    # Using small primes for demonstration consistency
    p = 61
    q = 53
    
    public_key, private_key = generate_keypair(p, q)
    
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")
    print("----------------------------------------")
    
    test_messages = [123, 89, 999, 2500, 3000]

    for i, msg in enumerate(test_messages):
        print(f"Test Case {i + 1}")
        print(f"Original Message: {msg}")
        
        encrypted_msg = encrypt(public_key, msg)
        print(f"Encrypted Message: {encrypted_msg}")
        
        decrypted_msg = decrypt(private_key, encrypted_msg)
        print(f"Decrypted Message: {decrypted_msg}")
        print("----------------------------------------")

if __name__ == '__main__':
    main()