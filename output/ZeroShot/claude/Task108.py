
import socket
import threading
import time
from typing import Dict, Set

class Task108:
    PORT = 8080
    SECRET_KEY = "MySecretKey12345"
    server_objects: Dict[str, str] = {}
    authenticated_clients: Set[str] = set()
    server_running = False
    
    @staticmethod
    def start_server():
        """Start the server to handle remote client requests"""
        Task108.server_objects = {
            "object1": "value1",
            "object2": "value2"
        }
        Task108.server_running = True
        
        def run_server():
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('localhost', Task108.PORT))
            server_socket.listen(5)
            server_socket.settimeout(1.0)
            print(f"Server started on port {Task108.PORT}")
            
            while Task108.server_running:
                try:
                    client_socket, address = server_socket.accept()
                    threading.Thread(target=Task108.handle_client, 
                                   args=(client_socket, address)).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Server error: {e}")
                    break
            
            server_socket.close()
        
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
    
    @staticmethod
    def handle_client(client_socket, address):
        """Handle individual client requests"""
        try:
            request = client_socket.recv(1024).decode('utf-8').strip()
            
            if not request:
                return
            
            parts = request.split('|')
            command = parts[0]
            client_id = str(address)
            
            # Authentication
            if command == "AUTH" and len(parts) == 2:
                if Task108.authenticate(parts[1]):
                    Task108.authenticated_clients.add(client_id)
                    response = "AUTH_SUCCESS"
                else:
                    response = "AUTH_FAILED"
            else:
                # Check authentication for other commands
                if client_id not in Task108.authenticated_clients:
                    response = "ERROR|Not authenticated"
                else:
                    response = Task108.process_command(parts)
            
            client_socket.send(response.encode('utf-8'))
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            client_socket.close()
    
    @staticmethod
    def authenticate(token):
        """Simple authentication method"""
        return token == Task108.SECRET_KEY
    
    @staticmethod
    def process_command(parts):
        """Process client commands"""
        command = parts[0]
        
        try:
            if command == "GET" and len(parts) == 2:
                key = Task108.sanitize_input(parts[1])
                value = Task108.server_objects.get(key)
                return f"SUCCESS|{value}" if value else "ERROR|Object not found"
            
            elif command == "SET" and len(parts) == 3:
                key = Task108.sanitize_input(parts[1])
                value = Task108.sanitize_input(parts[2])
                Task108.server_objects[key] = value
                return "SUCCESS|Object set"
            
            elif command == "DELETE" and len(parts) == 2:
                key = Task108.sanitize_input(parts[1])
                Task108.server_objects.pop(key, None)
                return "SUCCESS|Object deleted"
            
            elif command == "LIST":
                keys = ",".join(Task108.server_objects.keys())
                return f"SUCCESS|{keys}"
            
            else:
                return "ERROR|Unknown command"
        except Exception as e:
            return f"ERROR|{str(e)}"
    
    @staticmethod
    def sanitize_input(input_str):
        """Remove potentially dangerous characters"""
        import re
        return re.sub(r'[^a-zA-Z0-9_-]', '', input_str)
    
    @staticmethod
    def send_request(host, port, request):
        """Send request to server"""
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            client_socket.send(request.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            client_socket.close()
            return response
        except Exception as e:
            return f"ERROR|Connection failed: {str(e)}"

def main():
    print("=== Secure Remote Object Access System ===\\n")
    
    # Start server
    Task108.start_server()
    
    # Wait for server to start
    time.sleep(1)
    
    # Test Case 1: Authentication
    print("Test 1 - Authentication:")
    response = Task108.send_request("localhost", Task108.PORT, 
                                    f"AUTH|{Task108.SECRET_KEY}")
    print(f"Response: {response}\\n")
    
    # Test Case 2: Get object
    print("Test 2 - Get object:")
    response = Task108.send_request("localhost", Task108.PORT, "GET|object1")
    print(f"Response: {response}\\n")
    
    # Test Case 3: Set object
    print("Test 3 - Set object:")
    response = Task108.send_request("localhost", Task108.PORT, "SET|object3|value3")
    print(f"Response: {response}\\n")
    
    # Test Case 4: List objects
    print("Test 4 - List objects:")
    response = Task108.send_request("localhost", Task108.PORT, "LIST")
    print(f"Response: {response}\\n")
    
    # Test Case 5: Delete object
    print("Test 5 - Delete object:")
    response = Task108.send_request("localhost", Task108.PORT, "DELETE|object2")
    print(f"Response: {response}\\n")
    
    Task108.server_running = False
    time.sleep(1)

if __name__ == "__main__":
    main()
