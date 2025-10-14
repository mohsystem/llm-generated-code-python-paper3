
import socket
import threading
import sys
from typing import Set

PORT = 8888
MAX_CLIENTS = 100
MAX_MESSAGE_LENGTH = 1024
clients: Set[socket.socket] = set()
clients_lock = threading.Lock()

def main():
    print(f"Chat Server Starting on port {PORT}")
    start_server(PORT)

def start_server(port: int):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(MAX_CLIENTS)
        server_socket.settimeout(1.0)
        print(f"Server started. Waiting for clients on port {port}...")

        while True:
            try:
                if len(clients) >= MAX_CLIENTS:
                    continue
                    
                client_socket, address = server_socket.accept()
                client_socket.settimeout(300.0)
                
                with clients_lock:
                    clients.add(client_socket)
                
                print(f"New client connected: {address}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error accepting client: {e}")
                
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        shutdown(server_socket)

def handle_client(client_socket: socket.socket, address):
    client_id = f"{address[0]}:{address[1]}"
    
    try:
        client_socket.sendall(b"Welcome to the chat server!\\n")
        broadcast(f"{client_id} joined the chat\\n".encode('utf-8'), client_socket)
        
        buffer = b""
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                buffer += data
                while b"\\n" in buffer:
                    line, buffer = buffer.split(b"\\n", 1)
                    message = sanitize_message(line.decode('utf-8', errors='ignore'))
                    
                    if message.strip():
                        print(f"{client_id}: {message}")
                        broadcast(f"{client_id}: {message}\\n".encode('utf-8'), client_socket)
                        
                if len(buffer) > MAX_MESSAGE_LENGTH:
                    buffer = buffer[-MAX_MESSAGE_LENGTH:]
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving from client: {e}")
                break
                
    except Exception as e:
        print(f"Client handler error: {e}")
    finally:
        with clients_lock:
            clients.discard(client_socket)
        try:
            client_socket.close()
        except:
            pass
        broadcast(f"{client_id} left the chat\\n".encode('utf-8'), None)

def broadcast(message: bytes, sender_socket: socket.socket):
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH]
    
    with clients_lock:
        disconnected = set()
        for client in clients:
            if client != sender_socket:
                try:
                    client.sendall(message)
                except Exception as e:
                    disconnected.add(client)
        
        for client in disconnected:
            clients.discard(client)
            try:
                client.close()
            except:
                pass

def sanitize_message(message: str) -> str:
    if not message:
        return ""
    message = ''.join(char for char in message if 32 <= ord(char) <= 126 or char in '\\n\\r\\t')
    return message[:MAX_MESSAGE_LENGTH]

def shutdown(server_socket: socket.socket):
    print("Shutting down server...")
    with clients_lock:
        for client in clients:
            try:
                client.close()
            except:
                pass
        clients.clear()
    try:
        server_socket.close()
    except:
        pass

if __name__ == "__main__":
    main()
