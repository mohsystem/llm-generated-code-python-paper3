import socket
import threading
import os
import hashlib
import binascii
import re
import time
import socketserver
from pathlib import Path

USER_DB_FILE = "users.db"
PORT = 12345
HOST = "127.0.0.1"
VALID_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,16}$")

class PasswordUtils:
    ITERATIONS = 210000
    KEY_LENGTH = 32  # 256 bits
    SALT_LENGTH = 16

    @staticmethod
    def get_salt():
        return os.urandom(PasswordUtils.SALT_LENGTH)

    @staticmethod
    def hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PasswordUtils.ITERATIONS,
            dklen=PasswordUtils.KEY_LENGTH
        )

class UserStore:
    def __init__(self, filename):
        self.db_path = Path(filename).resolve()
        self.lock = threading.Lock()

    def add_user(self, username, password):
        if not (username and password and VALID_USERNAME_RE.match(username)):
            print(f"Error: Invalid username format for '{username}'.")
            return False
        
        with self.lock:
            # Check if user exists
            if self.db_path.exists():
                with open(self.db_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith(f"{username}:"):
                            print(f"Error: User '{username}' already exists.")
                            return False

            # Add new user
            salt = PasswordUtils.get_salt()
            hashed_password = PasswordUtils.hash_password(password, salt)
            
            salt_hex = binascii.hexlify(salt).decode('ascii')
            hash_hex = binascii.hexlify(hashed_password).decode('ascii')

            try:
                with open(self.db_path, "a", encoding="utf-8") as f:
                    f.write(f"{username}:{salt_hex}:{hash_hex}\n")
                return True
            except IOError as e:
                print(f"Error writing to user database: {e}")
                return False

    def authenticate(self, username, password):
        with self.lock:
            if not self.db_path.exists():
                return False
            
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) == 3 and parts[0] == username:
                            stored_salt = binascii.unhexlify(parts[1])
                            stored_hash = binascii.unhexlify(parts[2])
                            
                            provided_hash = PasswordUtils.hash_password(password, stored_salt)
                            
                            return hashlib.timing_safe_compare(stored_hash, provided_hash)
            except (IOError, binascii.Error) as e:
                print(f"Error authenticating user: {e}")

        return False

    def cleanup(self):
        with self.lock:
            if self.db_path.exists():
                try:
                    os.remove(self.db_path)
                except OSError as e:
                    print(f"Error cleaning up user database: {e}")


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(1024).strip().decode('utf-8')
            if not data:
                return
            
            parts = data.split(' ', 2)
            command = parts[0]
            
            response = "INVALID_COMMAND"
            if command == "REGISTER" and len(parts) == 3:
                username, password = parts[1], parts[2]
                if self.server.user_store.add_user(username, password):
                    response = "REGISTER_OK"
                else:
                    response = "REGISTER_FAIL"
            elif command == "LOGIN" and len(parts) == 3:
                username, password = parts[1], parts[2]
                if self.server.user_store.authenticate(username, password):
                    response = "LOGIN_OK"
                else:
                    response = "LOGIN_FAIL"
            
            self.request.sendall(f"{response}\n".encode('utf-8'))
        except Exception as e:
            print(f"Error handling request from {self.client_address}: {e}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, user_store):
        super().__init__(server_address, RequestHandlerClass)
        self.user_store = user_store
    allow_reuse_address = True

class Client:
    def send_request(self, request):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((HOST, PORT))
                sock.sendall(f"{request}\n".encode('utf-8'))
                response = sock.recv(1024).decode('utf-8').strip()
                return response
        except ConnectionRefusedError:
            return "ERROR: Connection refused. Is the server running?"
        except Exception as e:
            return f"ERROR: {e}"

def main():
    user_store = UserStore(USER_DB_FILE)
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler, user_store)
    
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print(f"Server listening on {HOST}:{PORT}")

    # Give server time to start
    time.sleep(0.5)

    client = Client()

    print("--- Test Cases ---")

    # Test Case 1: Register a new user
    print("Test 1: Register user 'testuser1'")
    response1 = client.send_request("REGISTER testuser1 StrongPass123!")
    print(f"Server response: {response1}")

    # Test Case 2: Successful login
    print("\nTest 2: Login with 'testuser1' (correct password)")
    response2 = client.send_request("LOGIN testuser1 StrongPass123!")
    print(f"Server response: {response2}")

    # Test Case 3: Failed login (wrong password)
    print("\nTest 3: Login with 'testuser1' (wrong password)")
    response3 = client.send_request("LOGIN testuser1 WrongPassword")
    print(f"Server response: {response3}")

    # Test Case 4: Failed login (non-existent user)
    print("\nTest 4: Login with 'no_such_user'")
    response4 = client.send_request("LOGIN no_such_user some_password")
    print(f"Server response: {response4}")

    # Test Case 5: Register another user and login
    print("\nTest 5: Register and login 'testuser2'")
    response5a = client.send_request("REGISTER testuser2 AnotherSecurePass$")
    print(f"Server response (Register): {response5a}")
    response5b = client.send_request("LOGIN testuser2 AnotherSecurePass$")
    print(f"Server response (Login): {response5b}")
    
    print("\n--- Tests Complete ---")

    server.shutdown()
    server.server_close()
    user_store.cleanup()
    print("Server stopped and cleaned up.")


if __name__ == "__main__":
    main()