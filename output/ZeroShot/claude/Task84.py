
import secrets
import string

class Task84:
    generated_ids = set()
    CHARACTERS = string.ascii_letters + string.digits
    SESSION_ID_LENGTH = 32
    
    @staticmethod
    def generate_session_id():
        while True:
            session_id = ''.join(secrets.choice(Task84.CHARACTERS) 
                                for _ in range(Task84.SESSION_ID_LENGTH))
            if session_id not in Task84.generated_ids:
                Task84.generated_ids.add(session_id)
                return session_id

if __name__ == "__main__":
    print("Test Case 1:", Task84.generate_session_id())
    print("Test Case 2:", Task84.generate_session_id())
    print("Test Case 3:", Task84.generate_session_id())
    print("Test Case 4:", Task84.generate_session_id())
    print("Test Case 5:", Task84.generate_session_id())
    
    # Verify uniqueness
    test_set = set()
    for i in range(5):
        test_set.add(Task84.generate_session_id())
    print("\\nAll generated IDs are unique:", len(test_set) == 5)
