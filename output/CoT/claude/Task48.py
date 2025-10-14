
import socket
import threading
import sys
from typing import Set

MAX_CLIENTS = 10
MAX_MESSAGE_LENGTH = 1024
PORT = 12345

class ChatServer:
    def __init__(self):
        self.clients: Set[ClientHandler] = set()
        self.lock = threading.Lock()
        self.server_socket = None
        
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', PORT))
            self.server_socket.listen(MAX_CLIENTS)
            print(f"Server started on port {PORT}")
            
            while True:
                if len(self.clients) >= MAX_CLIENTS:
                    continue
                client_socket, address = self.server_socket.accept()
                handler = ClientHandler(client_socket, address, self)
                with self.lock:
                    self.clients.add(handler)
                threading.Thread(target=handler.handle, daemon=True).start()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.shutdown()
    
    def broadcast(self, message: str, sender):
        if not message or len(message) > MAX_MESSAGE_LENGTH:
            return
        sanitized = self.sanitize_message(message)
        with self.lock:
            for client in self.clients:
                if client != sender:
                    client.send_message(sanitized)
    
    def sanitize_message(self, message: str) -> str:
        return ''.join(c for c in message if 32 <= ord(c) <= 126)
    
    def remove_client(self, client):
        with self.lock:
            self.clients.discard(client)
    
    def shutdown(self):
        if self.server_socket:
            self.server_socket.close()

class ClientHandler:
    def __init__(self, socket, address, server):
        self.socket = socket
        self.address = address
        self.server = server
        self.client_id = str(address)
    
    def handle(self):
        try:
            self.socket.sendall(b"Connected to chat server. Type messages to send.\\n")
            self.server.broadcast(f"{self.client_id} joined the chat", self)
            
            buffer = b""
            while True:
                data = self.socket.recv(1024)
                if not data:
                    break
                buffer += data
                while b'\\n' in buffer:
                    line, buffer = buffer.split(b'\\n', 1)
                    try:
                        message = line.decode('utf-8', errors='ignore').strip()
                        if len(message) > MAX_MESSAGE_LENGTH:
                            message = message[:MAX_MESSAGE_LENGTH]
                        if message:
                            self.server.broadcast(f"{self.client_id}: {message}", self)
                    except Exception:
                        continue
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            self.cleanup()
    
    def send_message(self, message: str):
        try:
            self.socket.sendall((message + "\\n").encode('utf-8'))
        except Exception:
            pass
    
    def cleanup(self):
        try:
            self.server.remove_client(self)
            self.server.broadcast(f"{self.client_id} left the chat", self)
            self.socket.close()
        except Exception:
            pass

class ChatClient:
    def __init__(self):
        self.socket = None
    
    def connect(self, host: str, port: int):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            def receive():
                try:
                    while True:
                        data = self.socket.recv(1024)
                        if not data:
                            break
                        print(data.decode('utf-8', errors='ignore'), end='')
                except Exception:
                    pass
            
            threading.Thread(target=receive, daemon=True).start()
        except Exception as e:
            print(f"Connection error: {e}")
    
    def send_message(self, message: str):
        if self.socket and message and len(message) <= MAX_MESSAGE_LENGTH:
            try:
                self.socket.sendall((message + "\\n").encode('utf-8'))
            except Exception:
                pass
    
    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

def main():
    import time
    
    print("Test Case 1: Start server")
    server = ChatServer()
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    print("\\nTest Case 2: Connect client 1")
    client1 = ChatClient()
    client1.connect('localhost', PORT)
    time.sleep(0.5)
    
    print("\\nTest Case 3: Connect client 2")
    client2 = ChatClient()
    client2.connect('localhost', PORT)
    time.sleep(0.5)
    
    print("\\nTest Case 4: Send messages")
    client1.send_message("Hello from client 1")
    time.sleep(0.5)
    client2.send_message("Hello from client 2")
    time.sleep(0.5)
    
    print("\\nTest Case 5: Disconnect clients")
    client1.disconnect()
    time.sleep(0.5)
    client2.disconnect()
    time.sleep(1)

if __name__ == "__main__":
    main()
