import uuid

def generate_session_id():
    """
    Generates and returns a random and unique session ID using UUID.
    :return: A unique session ID string.
    """
    return str(uuid.uuid4())

if __name__ == "__main__":
    print("Python Session IDs:")
    for i in range(5):
        print(f"Test Case {i + 1}: {generate_session_id()}")