import socket
import threading
import sys

# A lock to ensure thread-safe access to the clients list
clients_lock = threading.Lock()
clients = []
MAX_CLIENTS = 10
MAX_BUFFER_SIZE = 1024 # Prevents buffer overflow

def broadcast(message, sender_conn):
    """
    Broadcasts a message to all clients except the sender.
    """
    with clients_lock:
        for client_conn in clients:
            # Don't send the message back to the sender
            if client_conn != sender_conn:
                try:
                    client_conn.sendall(message)
                except socket.error:
                    # If sending fails, assume the client is disconnected and handle it
                    print(f"Failed to send to a client, closing connection.")
                    client_conn.close()
                    clients.remove(client_conn)

def handle_client(conn, addr):
    """
    Handles a single client connection.
    """
    client_name = f"Client-{addr[1]}"
    print(f"[NEW CONNECTION] {client_name} connected.")

    try:
        while True:
            # Receive message from the client, with a fixed buffer size
            try:
                data = conn.recv(MAX_BUFFER_SIZE)
                if not data:
                    # Empty data means client disconnected gracefully
                    break
                
                # Prepend sender info to the message
                message_to_broadcast = f"[{client_name}] {data.decode('utf-8')}".encode('utf-8')
                print(f"Received from {client_name}: {data.decode('utf-8')}")
                broadcast(message_to_broadcast, conn)

            except ConnectionResetError:
                # Client disconnected abruptly
                break
    finally:
        # Cleanup: close connection and remove from the list
        print(f"[DISCONNECTED] {client_name} disconnected.")
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()

def start_server(host, port):
    """
    Starts the chat server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allows reusing the address, helpful for quick restarts
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[LISTENING] Server is listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            
            with clients_lock:
                if len(clients) >= MAX_CLIENTS:
                    print(f"Max clients reached. Rejecting connection from {addr}")
                    conn.close()
                    continue

                clients.append(conn)
            
            # Start a new thread for each client
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True # Allows main thread to exit even if client threads are running
            thread.start()

    except OSError as e:
        print(f"Server error: {e}")
    finally:
        print("Shutting down server.")
        server_socket.close()

def main():
    # Test cases are not applicable in the traditional sense for a server.
    # The main function starts the server. To test, connect multiple clients
    # using a tool like netcat or a separate client program.
    # For example: `nc localhost 9090`
    HOST = '127.0.0.1'
    PORT = 9090
    
    if len(sys.argv) > 1:
        try:
            PORT = int(sys.argv[1])
        except ValueError:
            print("Invalid port number. Using default 9090.")

    print("--- Test Case 1: Starting server ---")
    print(f"--- Test Case 2: Server will listen on {HOST}:{PORT}")
    print(f"--- Test Case 3: Connect a client using 'nc {HOST} {PORT}'")
    print("--- Test Case 4: Messages will be broadcast to other connected clients.")
    print("--- Test Case 5: Disconnecting a client will be logged.")

    start_server(HOST, PORT)

if __name__ == "__main__":
    main()