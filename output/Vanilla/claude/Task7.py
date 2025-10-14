
import socket
import threading
import os
import time

class Task7:
    # User class to store credentials
    class User:
        def __init__(self, username, password):
            self.username = username
            self.password = password
    
    # Client class
    class ChatClient:
        def __init__(self, host, port):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
        
        def login(self, username, password):
            request = f"LOGIN:{username}:{password}"
            self.socket.send(request.encode())
            response = self.socket.recv(1024).decode()
            return response
        
        def close(self):
            self.socket.close()
    
    # Server class
    class ChatServer:
        def __init__(self, port):
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', port))
            self.server_socket.listen(5)
            self.users = {}
            self.user_file_path = "users.txt"
            self.load_users()
        
        def load_users(self):
            try:
                if not os.path.exists(self.user_file_path):
                    with open(self.user_file_path, 'w') as file:
                        file.write("alice:password123\\n")
                        file.write("bob:securepass\\n")
                        file.write("charlie:mypass456\\n")
                        file.write("david:test1234\\n")
                        file.write("eve:qwerty789\\n")
                
                with open(self.user_file_path, 'r') as file:
                    for line in file:
                        parts = line.strip().split(':')
                        if len(parts) == 2:
                            self.users[parts[0]] = parts[1]
            except Exception as e:
                print(f"Error loading users: {e}")
        
        def start(self):
            print(f"Server started on port {self.server_socket.getsockname()[1]}")
            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket,)
                    )
                    client_thread.start()
                except Exception as e:
                    print(f"Error accepting client: {e}")
                    break
        
        def handle_client(self, client_socket):
            try:
                request = client_socket.recv(1024).decode()
                response = self.process_request(request)
                client_socket.send(response.encode())
                client_socket.close()
            except Exception as e:
                print(f"Error handling client: {e}")
        
        def process_request(self, request):
            if not request or not request.startswith("LOGIN:"):
                return "ERROR:Invalid request format"
            
            parts = request.split(':')
            if len(parts) != 3:
                return "ERROR:Invalid login format"
            
            username = parts[1]
            password = parts[2]
            
            if username in self.users and self.users[username] == password:
                return "SUCCESS:Login successful"
            else:
                return "ERROR:Invalid username or password"
        
        def stop(self):
            self.server_socket.close()

def main():
    print("=== Chat System Test Cases ===\\n")
    
    # Start server in a separate thread
    server = Task7.ChatServer(8080)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Test cases
    test_cases = [
        ("alice", "password123"),
        ("bob", "securepass"),
        ("charlie", "wrongpass"),
        ("david", "test1234"),
        ("unknown", "password")
    ]
    
    for i, (username, password) in enumerate(test_cases, 1):
        try:
            print(f"Test Case {i}:")
            print(f"Username: {username}")
            print(f"Password: {password}")
            
            client = Task7.ChatClient("localhost", 8080)
            response = client.login(username, password)
            print(f"Response: {response}")
            client.close()
            print()
            
            time.sleep(0.5)
        except Exception as e:
            print(f"Client error: {e}")

if __name__ == "__main__":
    main()
