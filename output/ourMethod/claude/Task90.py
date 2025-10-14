
import socket
import threading
import sys
from typing import Set, Optional
import time

MAX_CLIENTS = 100
MAX_MESSAGE_LENGTH = 1024
MIN_PORT = 1024
MAX_PORT = 65535

clients: Set[socket.socket] = set()
clients_lock = threading.Lock()
client_counter = 0
counter_lock = threading.Lock()


def sanitize_message(message: str) -> str:
    """Sanitize message by removing non-printable characters."""
    if not message:
        return ""
    return ''.join(char for char in message if char.isprintable() or char.isspace()).strip()


def broadcast(message: str, sender_socket: Optional[socket.socket] = None) -> None:
    """Broadcast message to all connected clients."""
    with clients_lock:
        disconnected = []
        for client in clients:
            if client != sender_socket:
                try:
                    client.sendall((message + '\\n').encode('utf-8'))
                except Exception as e:
                    print(f"Broadcast error: {e}", file=sys.stderr)
                    disconnected.append(client)
        
        for client in disconnected:
            clients.discard(client)


def handle_client(client_socket: socket.socket, client_id: int) -> None:
    """Handle individual client connection."""
    global client_counter
    
    try:
        client_socket.settimeout(30.0)
        buffer = ""
        
        while True:
            try:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                buffer += data
                while '\\n' in buffer:
                    message, buffer = buffer.split('\\n', 1)
                    
                    if len(message) > MAX_MESSAGE_LENGTH:
                        message = message[:MAX_MESSAGE_LENGTH]
                    
                    sanitized = sanitize_message(message)
                    if sanitized:
                        broadcast_msg = f"[Client{client_id}]: {sanitized}"
                        broadcast(broadcast_msg, client_socket)
                        
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Client handler error: {e}", file=sys.stderr)
                break
                
    except Exception as e:
        print(f"Client error: {e}", file=sys.stderr)
    finally:
        with clients_lock:
            clients.discard(client_socket)
        with counter_lock:
            client_counter -= 1
        try:
            client_socket.close()
        except Exception:
            pass


def start_server(port: int) -> None:
    """Start the chat server on specified port."""
    global client_counter
    
    if not isinstance(port, int) or port < MIN_PORT or port > MAX_PORT:
        raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('127.0.0.1', port))
        server_socket.listen(5)
        server_socket.settimeout(5.0)
        print(f"Server started on port {port}")
        
        while True:
            with counter_lock:
                if client_counter >= MAX_CLIENTS:
                    break
            
            try:
                client_socket, address = server_socket.accept()
                
                with counter_lock:
                    if client_counter >= MAX_CLIENTS:
                        client_socket.close()
                        continue
                    client_counter += 1
                    current_id = client_counter
                
                with clients_lock:
                    clients.add(client_socket)
                
                thread = threading.Thread(target=handle_client, args=(client_socket, current_id))
                thread.daemon = True
                thread.start()
                
            except socket.timeout:
                break
            except Exception as e:
                print(f"Accept error: {e}", file=sys.stderr)
                
    finally:
        server_socket.close()


def test_client(port: int, client_name: str) -> None:
    """Test client connection."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', port))
        client_socket.sendall(f"Hello from {client_name}\\n".encode('utf-8'))
        
        client_socket.settimeout(2.0)
        response = client_socket.recv(1024).decode('utf-8')
        if response:
            print(f"{client_name} received: {response.strip()}")
        
        client_socket.close()
    except Exception as e:
        print(f"{client_name} error: {e}", file=sys.stderr)


def main() -> None:
    """Main function with test cases."""
    test_ports = [8080, 9000, 7777, 5555, 6666]
    
    for i, port in enumerate(test_ports, 1):
        print(f"\\nTest {i}: Start server on port {port}")
        
        server_thread = threading.Thread(target=start_server, args=(port,))
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(1)
        
        client_thread1 = threading.Thread(target=test_client, args=(port, "Client1"))
        client_thread1.daemon = True
        client_thread1.start()
        
        time.sleep(0.5)
        
        client_thread2 = threading.Thread(target=test_client, args=(port, "Client2"))
        client_thread2.daemon = True
        client_thread2.start()
        
        time.sleep(2)


if __name__ == "__main__":
    main()
