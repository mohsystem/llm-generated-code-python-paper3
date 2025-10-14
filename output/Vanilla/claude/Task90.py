
import socket
import threading
import time

class Task90:
    def __init__(self):
        self.clients = []
        self.client_counter = 0
        self.lock = threading.Lock()
    
    def start_server(self, port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            print(f"Chat server started on port {port}")
            
            while True:
                client_socket, address = server_socket.accept()
                with self.lock:
                    self.client_counter += 1
                    client_id = self.client_counter
                
                client_handler = ClientHandler(client_socket, client_id, self)
                with self.lock:
                    self.clients.append(client_handler)
                
                thread = threading.Thread(target=client_handler.run)
                thread.daemon = True
                thread.start()
                
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server_socket.close()
    
    def broadcast_message(self, message, sender):
        with self.lock:
            for client in self.clients:
                if client != sender:
                    client.send_message(message)
    
    def remove_client(self, client):
        with self.lock:
            if client in self.clients:
                self.clients.remove(client)


class ClientHandler:
    def __init__(self, socket, client_id, server):
        self.socket = socket
        self.client_id = client_id
        self.username = f"User{client_id}"
        self.server = server
    
    def run(self):
        try:
            self.send_message(f"Welcome to the chat! You are {self.username}")
            self.server.broadcast_message(f"{self.username} has joined the chat", self)
            
            while True:
                message = self.socket.recv(1024).decode('utf-8')
                if not message:
                    break
                
                message = message.strip()
                print(f"{self.username}: {message}")
                self.server.broadcast_message(f"{self.username}: {message}", self)
                
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            self.cleanup()
    
    def send_message(self, message):
        try:
            self.socket.send((message + '\\n').encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")
    
    def cleanup(self):
        self.server.remove_client(self)
        self.server.broadcast_message(f"{self.username} has left the chat", self)
        try:
            self.socket.close()
        except Exception as e:
            print(f"Error closing socket: {e}")


def test_client(client_num, port):
    try:
        time.sleep(0.2 * client_num)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', port))
        
        # Receive welcome message
        welcome = client_socket.recv(1024).decode('utf-8')
        print(f"Client {client_num} received: {welcome.strip()}")
        
        # Send messages
        client_socket.send(f"Hello from client {client_num}\\n".encode('utf-8'))
        time.sleep(0.5)
        client_socket.send(f"Message 2 from client {client_num}\\n".encode('utf-8'))
        
        # Receive broadcasts
        for _ in range(10):
            try:
                client_socket.settimeout(1.0)
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    print(f"Client {client_num} received: {message.strip()}")
            except socket.timeout:
                break
        
        client_socket.close()
    except Exception as e:
        print(f"Test client {client_num} error: {e}")


if __name__ == "__main__":
    # Test case: Start server on port 9999
    print("Test Case 1: Starting server on port 9999")
    
    server = Task90()
    server_thread = threading.Thread(target=server.start_server, args=(9999,))
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1)
    
    # Create 5 test clients
    client_threads = []
    for i in range(1, 6):
        thread = threading.Thread(target=test_client, args=(i, 9999))
        thread.daemon = True
        thread.start()
        client_threads.append(thread)
    
    # Wait for test clients to complete
    for thread in client_threads:
        thread.join(timeout=5)
    
    time.sleep(2)
    print("\\nTest completed successfully!")
