
import random
import string

class Task84:
    CHARACTERS = string.ascii_letters + string.digits
    SESSION_ID_LENGTH = 32
    used_session_ids = set()
    
    @staticmethod
    def generate_session_id():
        while True:
            session_id = ''.join(random.choice(Task84.CHARACTERS) for _ in range(Task84.SESSION_ID_LENGTH))
            if session_id not in Task84.used_session_ids:
                Task84.used_session_ids.add(session_id)
                return session_id

if __name__ == "__main__":
    print("Test Case 1:", Task84.generate_session_id())
    print("Test Case 2:", Task84.generate_session_id())
    print("Test Case 3:", Task84.generate_session_id())
    print("Test Case 4:", Task84.generate_session_id())
    print("Test Case 5:", Task84.generate_session_id())
