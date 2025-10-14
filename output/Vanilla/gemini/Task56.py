import secrets

def generate_token():
    """
    Generates a cryptographically secure URL-safe text string.
    This is suitable for password recovery tokens, session keys, etc.
    """
    # secrets.token_hex(16) creates a 32-character hex token.
    return secrets.token_hex(16)

def main():
    """Main function to run test cases."""
    print("Python: Generating 5 authentication tokens.")
    for i in range(5):
        token = generate_token()
        print(f"Test Case {i + 1}: {token}")

if __name__ == "__main__":
    main()