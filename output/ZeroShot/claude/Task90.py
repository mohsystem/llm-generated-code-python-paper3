
import socket
import threading
import sys

PORT = 8888
clients = []
clients_lock = threading.Lock()

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('', port))
        server_socket.listen(5)
        print(f"Chat Server starting on port {port}")
        print(f"Server is listening on port {port}")
        
        while True:
            client_socket, address = server_socket.accept()
            print(f"New client connected: {address}")
            
            client_handler = ClientHandler(client_socket, address)
            
            with clients_lock:
                clients.append(client_handler)
            
            thread = threading.Thread(target=client_handler.run)
            thread.daemon = True
            thread.start()
            
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()

def broadcast_message(message, sender):
    with clients_lock:
        for client in clients:
            if client != sender:
                client.send_message(message)

def remove_client(client):
    with clients_lock:
        if client in clients:
            clients.remove(client)

class ClientHandler:
    def __init__(self, client_socket, address):
        self.socket = client_socket
        self.address = address
        self.username = None
        
    def run(self):
        try:
            self.socket.send("Enter your username:\\n".encode('utf-8'))
            self.username = self.socket.recv(1024).decode('utf-8').strip()
            
            if not self.username:
                self.username = "Anonymous"
            
            print(f"{self.username} joined the chat")
            broadcast_message(f"{self.username} joined the chat", self)
            
            while True:
                message = self.socket.recv(1024).decode('utf-8').strip()
                
                if not message or message.lower() == "/quit":
                    break
                
                print(f"{self.username}: {message}")
                broadcast_message(f"{self.username}: {message}", self)
                
        except Exception as e:
            print(f"Client handler error: {e}")
        finally:
            self.cleanup()
    
    def send_message(self, message):
        try:
            self.socket.send((message + "\\n").encode('utf-8'))
        except:
            pass
    
    def cleanup(self):
        try:
            remove_client(self)
            if self.username:
                print(f"{self.username} left the chat")
                broadcast_message(f"{self.username} left the chat", self)
            self.socket.close()
        except:
            pass

if __name__ == "__main__":
    start_server(PORT)
