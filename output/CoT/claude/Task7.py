
import socket
import hashlib
import base64
import os
import threading
import time
from typing import Dict, Tuple

class Task7:
    class ChatServer:
        PORT = 8080
        USERS_FILE = "users.dat"
        MAX_LOGIN_ATTEMPTS = 3
        LOCKOUT_TIME = 300  # 5 minutes in seconds
        
        def __init__(self):
            self.login_attempts: Dict[str, int] = {}
            self.locked_accounts: Dict[str, float] = {}
            self.lock = threading.Lock()
        
        def start_server(self):
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('localhost', self.PORT))
                server_socket.listen(5)
                print(f"Server started on port {self.PORT}")
                
                while True:
                    client_socket, address = server_socket.accept()
                    thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    thread.daemon = True
                    thread.start()
            except Exception as e:
                print(f"Server error: {e}")
        
        def handle_client(self, client_socket):
            try:
                client_socket.settimeout(5.0)
                request = client_socket.recv(1024).decode('utf-8').strip()
                
                if not request:
                    response = "ERROR:Invalid request"
                else:
                    response = self.process_request(request)
                
                client_socket.sendall((response + '\\n').encode('utf-8'))
            except Exception as e:
                print(f"Client handling error: {e}")
            finally:
                client_socket.close()
        
        def process_request(self, request: str) -> str:
            # Input validation
            if not request or len(request) > 1000:
                return "ERROR:Invalid request format"
            
            parts = request.split(':', 2)
            if len(parts) != 3 or parts[0] != 'LOGIN':
                return "ERROR:Invalid request format"
            
            username = self.sanitize_input(parts[1])
            password = parts[2]
            
            # Validate username format
            if not self.is_valid_username(username):
                return "ERROR:Invalid username format"
            
            # Check if account is locked
            if self.is_account_locked(username):
                return "ERROR:Account temporarily locked"
            
            # Authenticate user
            if self.authenticate_user(username, password):
                with self.lock:
                    self.login_attempts.pop(username, None)
                return "SUCCESS:Login successful"
            else:
                self.increment_login_attempts(username)
                return "ERROR:Invalid credentials"
        
        def is_account_locked(self, username: str) -> bool:
            with self.lock:
                lockout_time = self.locked_accounts.get(username)
                if lockout_time:
                    if time.time() < lockout_time:
                        return True
                    else:
                        self.locked_accounts.pop(username, None)
                        self.login_attempts.pop(username, None)
            return False
        
        def increment_login_attempts(self, username: str):
            with self.lock:
                attempts = self.login_attempts.get(username, 0) + 1
                self.login_attempts[username] = attempts
                
                if attempts >= self.MAX_LOGIN_ATTEMPTS:
                    self.locked_accounts[username] = time.time() + self.LOCKOUT_TIME
        
        @staticmethod
        def is_valid_username(username: str) -> bool:
            if not username or len(username) > 50:
                return False
            return all(c.isalnum() or c == '_' for c in username)
        
        @staticmethod
        def sanitize_input(input_str: str) -> str:
            if not input_str:
                return ""
            return ''.join(c for c in input_str if c.isalnum() or c == '_')
        
        def authenticate_user(self, username: str, password: str) -> bool:
            try:
                if not os.path.exists(self.USERS_FILE):
                    self.initialize_users_file()
                
                with open(self.USERS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) == 3:
                            stored_username, stored_salt, stored_hash = parts
                            if stored_username == username:
                                computed_hash = self.hash_password(password, stored_salt)
                                return computed_hash == stored_hash
            except Exception as e:
                print(f"Authentication error: {e}")
            return False
        
        def initialize_users_file(self):
            try:
                users = [
                    ("user1", "password1"),
                    ("user2", "password2"),
                    ("admin", "admin123"),
                    ("testuser", "test123"),
                    ("alice", "alice456")
                ]
                
                with open(self.USERS_FILE, 'w', encoding='utf-8') as f:
                    for username, password in users:
                        salt = self.generate_salt()
                        hash_val = self.hash_password(password, salt)
                        f.write(f"{username}:{salt}:{hash_val}\\n")
            except Exception as e:
                print(f"Error initializing users file: {e}")
        
        @staticmethod
        def generate_salt() -> str:
            return base64.b64encode(os.urandom(16)).decode('utf-8')
        
        @staticmethod
        def hash_password(password: str, salt: str) -> str:
            hash_obj = hashlib.sha256()
            hash_obj.update(salt.encode('utf-8'))
            hash_obj.update(password.encode('utf-8'))
            return base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    class ChatClient:
        SERVER_HOST = 'localhost'
        SERVER_PORT = 8080
        CONNECTION_TIMEOUT = 5.0
        
        @staticmethod
        def login(username: str, password: str) -> str:
            # Input validation
            if not Task7.ChatClient.is_valid_input(username) or not Task7.ChatClient.is_valid_input(password):
                return "ERROR:Invalid input format"
            
            if len(username) > 50 or len(password) > 100:
                return "ERROR:Input too long"
            
            request = Task7.ChatClient.build_login_request(username, password)
            return Task7.ChatClient.send_request(request)
        
        @staticmethod
        def is_valid_input(input_str: str) -> bool:
            return input_str is not None and input_str and '\\n' not in input_str and '\\r' not in input_str
        
        @staticmethod
        def build_login_request(username: str, password: str) -> str:
            sanitized_username = ''.join(c for c in username if c.isalnum() or c == '_')
            return f"LOGIN:{sanitized_username}:{password}"
        
        @staticmethod
        def send_request(request: str) -> str:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(Task7.ChatClient.CONNECTION_TIMEOUT)
                client_socket.connect((Task7.ChatClient.SERVER_HOST, Task7.ChatClient.SERVER_PORT))
                
                client_socket.sendall((request + '\\n').encode('utf-8'))
                response = client_socket.recv(1024).decode('utf-8').strip()
                
                client_socket.close()
                return response if response else "ERROR:No response from server"
            except Exception as e:
                return f"ERROR:Connection failed - {e}"
        
        @staticmethod
        def interactive_login():
            username = input("Enter username: ").strip()
            password = input("Enter password: ")
            
            response = Task7.ChatClient.login(username, password)
            print(f"Server response: {response}")

def main():
    # Start server in a separate thread
    server = Task7.ChatServer()
    server_thread = threading.Thread(target=server.start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Test cases
    print("=== Running Test Cases ===\\n")
    
    # Test case 1: Valid login
    print("Test 1 - Valid user login:")
    response1 = Task7.ChatClient.login("user1", "password1")
    print(f"Response: {response1}\\n")
    
    # Test case 2: Invalid password
    print("Test 2 - Invalid password:")
    response2 = Task7.ChatClient.login("user1", "wrongpassword")
    print(f"Response: {response2}\\n")
    
    # Test case 3: Non-existent user
    print("Test 3 - Non-existent user:")
    response3 = Task7.ChatClient.login("nonexistent", "password")
    print(f"Response: {response3}\\n")
    
    # Test case 4: Valid admin login
    print("Test 4 - Admin login:")
    response4 = Task7.ChatClient.login("admin", "admin123")
    print(f"Response: {response4}\\n")
    
    # Test case 5: Empty credentials
    print("Test 5 - Empty credentials:")
    response5 = Task7.ChatClient.login("", "")
    print(f"Response: {response5}\\n")

if __name__ == "__main__":
    main()
