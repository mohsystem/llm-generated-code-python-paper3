import socket
import threading
import sys
from typing import List

HOST = '0.0.0.0'
PORT = 12345
MAX_CLIENTS = 10
BUFFER_SIZE = 1024

clients: List[socket.socket] = []
clients_lock = threading.Lock()
client_counter = 0

def broadcast(message: bytes, sender_socket: socket.socket):
    """Broadcasts a message to all clients except the sender."""
    with clients_lock:
        # Create a copy of the list for safe iteration
        for client in list(clients):
            if client != sender_socket:
                try:
                    client.sendall(message)
                except (socket.error, BrokenPipeError):
                    # Client is disconnected, remove it
                    print(f"Client {client.getpeername()} disconnected. Removing.")
                    client.close()
                    if client in clients:
                        clients.remove(client)

def handle_client(client_socket: socket.socket, addr):
    """Handles a single client connection."""
    global client_counter
    with clients_lock:
        client_id = client_counter
        client_counter += 1
    
    print(f"Accepted connection from {addr}, assigned as Client-{client_id}")

    try:
        while True:
            try:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    # Client disconnected gracefully
                    break
                
                # Input validation: ensure data is not empty
                if data.strip():
                    message = f"[Client-{client_id}]: ".encode('utf-8') + data
                    print(f"Received from {addr} (Client-{client_id}): {data.decode('utf-8').strip()}")
                    broadcast(message, client_socket)
            except ConnectionResetError:
                # Client disconnected abruptly
                break
            except socket.error as e:
                print(f"Socket error with {addr}: {e}")
                break

    finally:
        print(f"Closing connection for {addr} (Client-{client_id})")
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        broadcast(f"Client-{client_id} has left the chat.".encode('utf-8'), client_socket)
        client_socket.close()

def main():
    """Main function to start the server."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Python Chat Server listening on {HOST}:{PORT}")

        while True:
            try:
                client_socket, addr = server_socket.accept()
                
                with clients_lock:
                    if len(clients) >= MAX_CLIENTS:
                        print(f"Refusing connection from {addr}: server full.")
                        client_socket.sendall(b"Server is full. Please try again later.\n")
                        client_socket.close()
                        continue
                    
                    clients.append(client_socket)

                thread = threading.Thread(target=handle_client, args=(client_socket, addr))
                thread.daemon = True
                thread.start()

            except Exception as e:
                print(f"Error accepting connections: {e}")
                break
    
    except socket.error as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Server is shutting down.")
    finally:
        with clients_lock:
            for client in clients:
                client.close()
        server_socket.close()
        print("Server shutdown complete.")

if __name__ == "__main__":
    # A main method is provided to run the server.
    # To test, you can use a netcat or telnet client.
    # For example, in 5 separate terminals, run:
    # 1. Terminal 1: nc localhost 12345
    # 2. Terminal 2: nc localhost 12345
    # 3. Terminal 3: nc localhost 12345
    # 4. Terminal 4: nc localhost 12345
    # 5. Terminal 5: nc localhost 12345
    # Type messages in any terminal, and they should appear in all others.
    main()