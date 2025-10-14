import socket
import threading

# List to keep track of connected client sockets
clients = []
# Lock to ensure thread-safe access to the clients list
clients_lock = threading.Lock()
PORT = 8080
HOST = '0.0.0.0' # Listen on all available network interfaces
BUFFER_SIZE = 1024

def broadcast(message, sender_socket):
    """
    Sends a message to all clients except the sender.
    Secure: Uses a lock to prevent race conditions on the clients list.
    """
    with clients_lock:
        for client in clients:
            # Send to everyone, including the sender. Can be modified to exclude sender.
            # if client != sender_socket:
            try:
                client.sendall(message)
            except socket.error:
                # Secure: Handle broken connections gracefully.
                # The cleanup for this broken client will be handled in its own thread.
                pass

def handle_client(client_socket, addr):
    """
    Handles a single client connection.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    
    # Add the new client to the list in a thread-safe way
    with clients_lock:
        clients.append(client_socket)
    
    try:
        broadcast(f"Server: {addr} has joined the chat.".encode('utf-8'), client_socket)
        while True:
            # Secure: Receive a fixed buffer size to prevent buffer overflow issues.
            message = client_socket.recv(BUFFER_SIZE)
            if not message:
                # An empty message means the client has disconnected.
                break
            
            # Prepare message for broadcast
            broadcast_message = f"[{addr}]: ".encode('utf-8') + message
            print(f"Received from {addr}: {message.decode('utf-8').strip()}")
            broadcast(broadcast_message, client_socket)
            
    except ConnectionResetError:
        print(f"[DISCONNECTED] {addr} disconnected unexpectedly.")
    except Exception as e:
        print(f"[ERROR] An error occurred with {addr}: {e}")
    finally:
        # Secure: Cleanup resources regardless of how the connection ended.
        print(f"[DISCONNECTED] {addr} disconnected.")
        broadcast(f"Server: {addr} has left the chat.".encode('utf-8'), client_socket)
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()

def start_server():
    """
    Starts the chat server.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # This allows reusing the address, helpful for quick server restarts.
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5) # Allow up to 5 pending connections
        print(f"[LISTENING] Server is listening on {HOST}:{PORT}")
        
        while True:
            client_socket, addr = server.accept()
            # Create a new thread for each client to handle them concurrently.
            thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            thread.daemon = True # Allows main program to exit even if threads are running
            thread.start()
            
    except OSError as e:
        print(f"[ERROR] Could not start server: {e}")
    finally:
        server.close()
        print("[SHUTDOWN] Server has been shut down.")

if __name__ == "__main__":
    """
    How to test this server:
    1. Run this Python script. The server will start listening on port 8080.
    2. Open a terminal/command prompt and connect using a client like telnet or netcat:
       `telnet localhost 8080` or `nc localhost 8080`
    3. Open another terminal and connect again. You now have two clients.
    4. Type a message in one terminal and press Enter. It should appear in the other terminal.
    5. Repeat with more clients (e.g., 5 test cases means 5 connected clients).
    6. Close a client's terminal (Ctrl+D in nc, Ctrl+] then 'quit' in telnet). 
       The server will handle the disconnection.
    """
    start_server()