import hashlib

def hash_password(password, salt):
    """
    Computes the SHA-256 hash of a password combined with a salt.

    :param password: The password to hash (string).
    :param salt: The salt to combine with the password (string).
    :return: The hexadecimal representation of the hash (string).
    """
    combined = salt + password
    hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return hashed

def main():
    # Test Case 1
    pass1 = "password123"
    salt1 = "randomsalt1"
    print(f"Password: {pass1}, Salt: {salt1}")
    print(f"Hash: {hash_password(pass1, salt1)}\n")

    # Test Case 2
    pass2 = "MyP@ssw0rd"
    salt2 = "salty-salty"
    print(f"Password: {pass2}, Salt: {salt2}")
    print(f"Hash: {hash_password(pass2, salt2)}\n")

    # Test Case 3
    pass3 = "topsecret"
    salt3 = "another-salt"
    print(f"Password: {pass3}, Salt: {salt3}")
    print(f"Hash: {hash_password(pass3, salt3)}\n")

    # Test Case 4 (Empty Password)
    pass4 = ""
    salt4 = "emptypass"
    print(f"Password: '{pass4}', Salt: {salt4}")
    print(f"Hash: {hash_password(pass4, salt4)}\n")

    # Test Case 5 (Empty Salt)
    pass5 = "short"
    salt5 = ""
    print(f"Password: {pass5}, Salt: '{salt5}'")
    print(f"Hash: {hash_password(pass5, salt5)}\n")

if __name__ == "__main__":
    main()