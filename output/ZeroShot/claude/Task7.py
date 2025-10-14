
import socket
import hashlib
import base64
import os
import threading
import time
from secrets import token_bytes

class Task7:
    class ChatServer:
        def __init__(self, port=8888):
            self.port = port
            self.user_file = "users.txt"
            
        def start(self):
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('localhost', self.port))
            server_socket.listen(5)
            print(f"Server started on port {self.port}")
            
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
        
        def handle_client(self, client_socket):
            try:
                request = client_socket.recv(1024).decode('utf-8')
                
                if request.startswith("LOGIN:"):
                    parts = request[6:].split(":", 1)
                    if len(parts) == 2:
                        username = self.sanitize_input(parts[0])
                        password = parts[1]
                        
                        if self.authenticate_user(username, password):
                            response = "SUCCESS:Login successful"
                        else:
                            response = "FAILURE:Invalid credentials"
                    else:
                        response = "FAILURE:Invalid request format"
                else:
                    response = "FAILURE:Unknown request"
                
                client_socket.send(response.encode('utf-8'))
                
            except Exception as e:
                print(f"Error: {e}")
            finally:
                client_socket.close()
        
        def sanitize_input(self, input_str):
            if not input_str:
                return ""
            sanitized = ''.join(c for c in input_str if c.isalnum() or c == '_')
            return sanitized[:50]
        
        def authenticate_user(self, username, password):
            try:
                if not os.path.exists(self.user_file):
                    self.initialize_user_file()
                
                with open(self.user_file, 'r') as file:
                    for line in file:
                        parts = line.strip().split(":", 2)
                        if len(parts) == 3:
                            stored_user, stored_salt, stored_hash = parts
                            
                            if stored_user == username:
                                hashed_password = self.hash_password(password, stored_salt)
                                return hashed_password == stored_hash
                
            except Exception as e:
                print(f"Authentication error: {e}")
            
            return False
        
        def initialize_user_file(self):
            test_users = ["alice", "bob", "charlie", "david", "eve"]
            test_passwords = ["password123", "secure456", "test789", "demo000", "chat111"]
            
            with open(self.user_file, 'w') as file:
                for user, password in zip(test_users, test_passwords):
                    salt = self.generate_salt()
                    hashed_password = self.hash_password(password, salt)
                    file.write(f"{user}:{salt}:{hashed_password}\\n")
        
        def generate_salt(self):
            return base64.b64encode(token_bytes(16)).decode('utf-8')
        
        def hash_password(self, password, salt):
            combined = salt.encode('utf-8') + password.encode('utf-8')
            hashed = hashlib.sha256(combined).digest()
            return base64.b64encode(hashed).decode('utf-8')
    
    class ChatClient:
        def __init__(self, server_address='localhost', server_port=8888):
            self.server_address = server_address
            self.server_port = server_port
        
        def login(self, username, password):
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.server_address, self.server_port))
                
                request = self.build_login_request(username, password)
                client_socket.send(request.encode('utf-8'))
                
                response = client_socket.recv(1024).decode('utf-8')
                
                client_socket.close()
                return response
                
            except Exception as e:
                return f"FAILURE:Connection error - {str(e)}"
        
        def build_login_request(self, username, password):
            return f"LOGIN:{username}:{password}"

# Main function with test cases
def main():
    # Start server in a separate thread
    server = Task7.ChatServer()
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(2)
    
    # Test cases
    client = Task7.ChatClient()
    
    print("Test Case 1 - Valid login (alice):")
    response1 = client.login("alice", "password123")
    print(response1)
    
    print("\\nTest Case 2 - Valid login (bob):")
    response2 = client.login("bob", "secure456")
    print(response2)
    
    print("\\nTest Case 3 - Invalid password:")
    response3 = client.login("alice", "wrongpassword")
    print(response3)
    
    print("\\nTest Case 4 - Non-existent user:")
    response4 = client.login("hacker", "password")
    print(response4)
    
    print("\\nTest Case 5 - Valid login (charlie):")
    response5 = client.login("charlie", "test789")
    print(response5)

if __name__ == "__main__":
    main()
