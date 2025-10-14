
import socket
import threading
import hashlib
import secrets
import base64
import time
from concurrent.futures import ThreadPoolExecutor

class Task108:
    PORT = 8443
    SECRET_KEY = "MySecureKey12345"
    MAX_CONNECTIONS = 10
    SESSION_TIMEOUT = 300  # 5 minutes in seconds
    
    class SecureObjectStore:
        def __init__(self):
            self.store = {}
            self.session_tokens = {}
            self.lock = threading.Lock()
        
        def authenticate(self, username, password):
            # In production, use secure password hashing (bcrypt, Argon2)
            hashed_password = self.hash_password(password)
            return username == "admin" and self.hash_password("admin123") == hashed_password
        
        def create_session(self, username):
            token = secrets.token_urlsafe(32)
            with self.lock:
                self.session_tokens[token] = time.time()
            return token
        
        def validate_session(self, token):
            with self.lock:
                if token not in self.session_tokens:
                    return False
                if time.time() - self.session_tokens[token] > self.SESSION_TIMEOUT:
                    del self.session_tokens[token]
                    return False
                return True
        
        def put(self, key, value, token):
            if not self.validate_session(token):
                return "ERROR: Invalid session"
            if not self.is_valid_key(key):
                return "ERROR: Invalid key format"
            if not self.is_valid_value(value):
                return "ERROR: Invalid value"
            with self.lock:
                self.store[self.sanitize(key)] = self.sanitize(value)
            return "SUCCESS: Object stored"
        
        def get(self, key, token):
            if not self.validate_session(token):
                return "ERROR: Invalid session"
            if not self.is_valid_key(key):
                return "ERROR: Invalid key format"
            with self.lock:
                value = self.store.get(self.sanitize(key))
            return str(value) if value is not None else "ERROR: Key not found"
        
        def delete(self, key, token):
            if not self.validate_session(token):
                return "ERROR: Invalid session"
            if not self.is_valid_key(key):
                return "ERROR: Invalid key format"
            with self.lock:
                removed = self.store.pop(self.sanitize(key), None)
            return "SUCCESS: Object deleted" if removed is not None else "ERROR: Key not found"
        
        def list_keys(self, token):
            if not self.validate_session(token):
                return "ERROR: Invalid session"
            with self.lock:
                keys = ",".join(self.store.keys())
            return f"KEYS: {keys}"
        
        @staticmethod
        def is_valid_key(key):
            import re
            return key is not None and re.match(r'^[a-zA-Z0-9_-]{1,50}$', key) is not None
        
        @staticmethod
        def is_valid_value(value):
            return value is not None and len(value) <= 1000
        
        @staticmethod
        def sanitize(input_str):
            import re
            return re.sub(r'[^a-zA-Z0-9_\\-\\s]', '', input_str)
        
        @staticmethod
        def hash_password(password):
            return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    class ClientHandler:
        def __init__(self, client_socket, store):
            self.client_socket = client_socket
            self.store = store
            self.session_token = None
        
        def handle(self):
            try:
                self.client_socket.settimeout(30)
                self.client_socket.sendall(b"Welcome to Secure Object Store. Commands: AUTH|PUT|GET|DELETE|LIST|QUIT\\n")
                
                buffer = b""
                while True:
                    chunk = self.client_socket.recv(4096)
                    if not chunk:
                        break
                    
                    buffer += chunk
                    if b'\\n' in buffer:
                        line, buffer = buffer.split(b'\\n', 1)
                        command = line.decode('utf-8').strip()
                        
                        if len(command) > 2000:
                            self.client_socket.sendall(b"ERROR: Command too long\\n")
                            continue
                        
                        response = self.process_command(command)
                        self.client_socket.sendall((response + "\\n").encode('utf-8'))
                        
                        if command.upper() == "QUIT":
                            break
            except socket.timeout:
                print("Client timeout")
            except Exception as e:
                print(f"Error handling client: {e}")
            finally:
                self.client_socket.close()
        
        def process_command(self, command):
            parts = command.split('|')
            if len(parts) == 0:
                return "ERROR: Invalid command"
            
            cmd = parts[0].upper()
            
            try:
                if cmd == "AUTH":
                    if len(parts) != 3:
                        return "ERROR: Usage: AUTH|username|password"
                    if self.store.authenticate(parts[1], parts[2]):
                        self.session_token = self.store.create_session(parts[1])
                        return f"SUCCESS: Authenticated. Token: {self.session_token}"
                    return "ERROR: Authentication failed"
                
                elif cmd == "PUT":
                    if len(parts) != 3:
                        return "ERROR: Usage: PUT|key|value"
                    if self.session_token is None:
                        return "ERROR: Not authenticated"
                    return self.store.put(parts[1], parts[2], self.session_token)
                
                elif cmd == "GET":
                    if len(parts) != 2:
                        return "ERROR: Usage: GET|key"
                    if self.session_token is None:
                        return "ERROR: Not authenticated"
                    return self.store.get(parts[1], self.session_token)
                
                elif cmd == "DELETE":
                    if len(parts) != 2:
                        return "ERROR: Usage: DELETE|key"
                    if self.session_token is None:
                        return "ERROR: Not authenticated"
                    return self.store.delete(parts[1], self.session_token)
                
                elif cmd == "LIST":
                    if self.session_token is None:
                        return "ERROR: Not authenticated"
                    return self.store.list_keys(self.session_token)
                
                elif cmd == "QUIT":
                    return "Goodbye"
                
                else:
                    return "ERROR: Unknown command"
            except Exception as e:
                return f"ERROR: {str(e)}"
    
    @staticmethod
    def start_server():
        store = Task108.SecureObjectStore()
        executor = ThreadPoolExecutor(max_workers=Task108.MAX_CONNECTIONS)
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', Task108.PORT))
        server_socket.listen(Task108.MAX_CONNECTIONS)
        
        print(f"Secure Object Store Server started on port {Task108.PORT}")
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                handler = Task108.ClientHandler(client_socket, store)
                executor.submit(handler.handle)
            except Exception as e:
                print(f"Error accepting client: {e}")
    
    @staticmethod
    def send_command(host, port, command):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)
            client_socket.connect((host, port))
            
            client_socket.recv(1024)  # Welcome message
            client_socket.sendall((command + "\\n").encode('utf-8'))
            response = client_socket.recv(4096).decode('utf-8').strip()
            client_socket.close()
            return response
        except Exception as e:
            return f"ERROR: {str(e)}"

def main():
    # Start server in a separate thread
    server_thread = threading.Thread(target=Task108.start_server, daemon=True)
    server_thread.start()
    
    time.sleep(2)  # Wait for server to start
    
    # Test cases
    print("=== Test Case 1: Authentication ===")
    response1 = Task108.send_command("localhost", Task108.PORT, "AUTH|admin|admin123")
    print(response1)
    
    print("\\n=== Test Case 2: Put Object ===")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("localhost", Task108.PORT))
        client.recv(1024)
        client.sendall(b"AUTH|admin|admin123\\n")
        client.recv(1024)
        client.sendall(b"PUT|key1|value1\\n")
        print(client.recv(1024).decode('utf-8').strip())
        client.close()
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("\\n=== Test Case 3: Get Object ===")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("localhost", Task108.PORT))
        client.recv(1024)
        client.sendall(b"AUTH|admin|admin123\\n")
        client.recv(1024)
        client.sendall(b"PUT|key1|value1\\n")
        client.recv(1024)
        client.sendall(b"GET|key1\\n")
        print(client.recv(1024).decode('utf-8').strip())
        client.close()
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("\\n=== Test Case 4: List Objects ===")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("localhost", Task108.PORT))
        client.recv(1024)
        client.sendall(b"AUTH|admin|admin123\\n")
        client.recv(1024)
        client.sendall(b"PUT|key1|value1\\n")
        client.recv(1024)
        client.sendall(b"PUT|key2|value2\\n")
        client.recv(1024)
        client.sendall(b"LIST\\n")
        print(client.recv(1024).decode('utf-8').strip())
        client.close()
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("\\n=== Test Case 5: Delete Object ===")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("localhost", Task108.PORT))
        client.recv(1024)
        client.sendall(b"AUTH|admin|admin123\\n")
        client.recv(1024)
        client.sendall(b"PUT|key1|value1\\n")
        client.recv(1024)
        client.sendall(b"DELETE|key1\\n")
        print(client.recv(1024).decode('utf-8').strip())
        client.close()
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()
