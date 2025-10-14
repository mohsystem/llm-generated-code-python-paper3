
import hashlib

def hash_password(password, salt):
    combined = password + salt
    hash_object = hashlib.sha256(combined.encode('utf-8'))
    return hash_object.hexdigest()

if __name__ == "__main__":
    # Test case 1
    hash1 = hash_password("password123", "randomsalt")
    print(f"Test 1: {hash1}")
    
    # Test case 2
    hash2 = hash_password("mySecurePass", "salt456")
    print(f"Test 2: {hash2}")
    
    # Test case 3
    hash3 = hash_password("admin", "abcdef")
    print(f"Test 3: {hash3}")
    
    # Test case 4
    hash4 = hash_password("test", "xyz")
    print(f"Test 4: {hash4}")
    
    # Test case 5
    hash5 = hash_password("", "emptysalt")
    print(f"Test 5: {hash5}")
