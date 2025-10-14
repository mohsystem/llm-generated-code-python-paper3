
import socket
import threading
import re
from typing import Set, Optional
import time

MAX_MESSAGE_LENGTH: int = 1024
MAX_USERNAME_LENGTH: int = 50
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
SERVER_PORT: int = 12345


class ChatServer:
    def __init__(self) -> None:
        self.clients: Set['ClientHandler'] = set()
        self.server_socket: Optional[socket.socket] = None
        self.lock = threading.Lock()
        self.running = False
    
    def start(self, port: int) -> bool:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            self.running = True
            print(f"Server started on port {port}")
            return True
        except OSError as e:
            print(f"Failed to start server: {e}")
            return False
    
    def accept_clients(self, max_clients: int) -> None:
        count = 0
        while count < max_clients and self.running:
            try:
                if self.server_socket is None:
                    break
                client_socket, _ = self.server_socket.accept()
                handler = ClientHandler(client_socket, self)
                with self.lock:
                    self.clients.add(handler)
                thread = threading.Thread(target=handler.run, daemon=True)
                thread.start()
                count += 1
            except socket.timeout:
                continue
            except OSError:
                break
    
    def broadcast(self, message: str, sender: Optional['ClientHandler']) -> None:
        if message is None or len(message) > MAX_MESSAGE_LENGTH:
            return
        sanitized = self._sanitize_message(message)
        with self.lock:
            for client in self.clients:
                if client != sender:
                    client.send_message(sanitized)
    
    def remove_client(self, client: 'ClientHandler') -> None:
        with self.lock:
            self.clients.discard(client)
    
    def shutdown(self) -> None:
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        with self.lock:
            for client in list(self.clients):
                client.close()
    
    def _sanitize_message(self, message: str) -> str:
        if message is None:
            return ""
        return ''.join(c for c in message if ord(c) >= 32 and ord(c) != 127)


class ClientHandler:
    def __init__(self, client_socket: socket.socket, server: ChatServer) -> None:
        self.socket = client_socket
        self.server = server
        self.username: Optional[str] = None
        self.running = True
    
    def run(self) -> None:
        try:
            self.socket.settimeout(5.0)
            username_bytes = self.socket.recv(MAX_USERNAME_LENGTH + 10)
            username = username_bytes.decode('utf-8', errors='ignore').strip()
            
            if not self._validate_username(username):
                self.close()
                return
            
            self.username = username
            self.server.broadcast(f"{self.username} joined the chat", self)
            
            while self.running:
                data = self.socket.recv(MAX_MESSAGE_LENGTH + 100)
                if not data:
                    break
                
                message = data.decode('utf-8', errors='ignore').strip()
                if len(message) > MAX_MESSAGE_LENGTH:
                    message = message[:MAX_MESSAGE_LENGTH]
                
                self.server.broadcast(f"{self.username}: {message}", self)
        except (OSError, UnicodeDecodeError):
            pass
        finally:
            self.server.remove_client(self)
            if self.username:
                self.server.broadcast(f"{self.username} left the chat", self)
            self.close()
    
    def _validate_username(self, username: str) -> bool:
        if not username or len(username) > MAX_USERNAME_LENGTH:
            return False
        return VALID_USERNAME_PATTERN.match(username) is not None
    
    def send_message(self, message: str) -> None:
        try:
            if self.socket and message:
                self.socket.sendall((message + '\\n').encode('utf-8'))
        except OSError:
            pass
    
    def close(self) -> None:
        self.running = False
        try:
            if self.socket:
                self.socket.close()
        except OSError:
            pass


class ChatClient:
    def __init__(self) -> None:
        self.socket: Optional[socket.socket] = None
    
    def connect(self, host: str, port: int, username: str) -> bool:
        if not username or len(username) > MAX_USERNAME_LENGTH:
            return False
        if not VALID_USERNAME_PATTERN.match(username):
            return False
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(2.0)
            self.socket.connect((host, port))
            self.socket.sendall((username + '\\n').encode('utf-8'))
            return True
        except OSError:
            return False
    
    def send_message(self, message: str) -> None:
        if self.socket and message and len(message) <= MAX_MESSAGE_LENGTH:
            try:
                self.socket.sendall((message + '\\n').encode('utf-8'))
            except OSError:
                pass
    
    def receive_message(self, timeout_ms: int) -> Optional[str]:
        try:
            if self.socket:
                self.socket.settimeout(timeout_ms / 1000.0)
                data = self.socket.recv(MAX_MESSAGE_LENGTH + 100)
                return data.decode('utf-8', errors='ignore').strip() if data else None
        except OSError:
            return None
        return None
    
    def disconnect(self) -> None:
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass


def main() -> None:
    # Test case 1: Server starts
    print("Test 1: Server startup")
    server = ChatServer()
    server.start(SERVER_PORT)
    
    # Test case 2: Multiple clients connect
    print("\\nTest 2: Multiple clients connect")
    client1 = ChatClient()
    client2 = ChatClient()
    
    server_thread = threading.Thread(target=lambda: server.accept_clients(5), daemon=True)
    server_thread.start()
    
    time.sleep(0.1)
    
    connected1 = client1.connect("localhost", SERVER_PORT, "Alice")
    connected2 = client2.connect("localhost", SERVER_PORT, "Bob")
    
    print(f"Client1 connected: {connected1}")
    print(f"Client2 connected: {connected2}")
    
    time.sleep(0.1)
    
    # Test case 3: Message broadcasting
    print("\\nTest 3: Message broadcasting")
    client1.send_message("Hello from Alice")
    
    time.sleep(0.1)
    
    msg = client2.receive_message(500)
    print(f"Client2 received: {msg}")
    
    # Test case 4: Invalid username rejection
    print("\\nTest 4: Invalid username rejection")
    client3 = ChatClient()
    connected3 = client3.connect("localhost", SERVER_PORT, "Invalid@User!")
    print(f"Client3 with invalid username connected: {connected3}")
    
    # Test case 5: Message length validation
    print("\\nTest 5: Message length validation")
    long_msg = "x" * 2000
    client1.send_message(long_msg)
    
    time.sleep(0.1)
    
    truncated = client2.receive_message(500)
    print(f"Long message handled: {truncated is not None}")
    
    # Cleanup
    client1.disconnect()
    client2.disconnect()
    client3.disconnect()
    server.shutdown()
    
    print("\\nAll tests completed")


if __name__ == "__main__":
    main()
