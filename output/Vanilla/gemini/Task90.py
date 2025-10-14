import socket
import threading
import sys

# List to keep track of connected client sockets
clients = []
# Lock to ensure thread-safe access to the clients list
clients_lock = threading.Lock()

def broadcast(message, sender_socket):
    """
    Sends a message to all clients except the sender.
    """
    with clients_lock:
        for client_socket in clients:
            if client_socket != sender_socket:
                try:
                    client_socket.send(message)
                except socket.error:
                    # Assume client is disconnected and remove it
                    client_socket.close()
                    clients.remove(client_socket)

def handle_client(client_socket, addr):
    """
    Handles a single client connection.
    """
    client_name = f"{addr[0]}:{addr[1]}"
    print(f"New connection from {client_name}")
    
    with clients_lock:
        clients.append(client_socket)

    join_msg = f"Server: {client_name} has joined the chat.\n".encode('utf-8')
    print(join_msg.decode('utf-8').strip())
    broadcast(join_msg, client_socket) # Notify others

    try:
        while True:
            message = client_socket.recv(1024)
            if not message or message.decode('utf-8').strip().lower() == 'exit':
                break
            
            broadcast_msg = f"{client_name}: {message.decode('utf-8')}".encode('utf-8')
            print(f"Received: {broadcast_msg.decode('utf-8').strip()}")
            broadcast(broadcast_msg, client_socket)

    except (ConnectionResetError, BrokenPipeError):
        print(f"Client {client_name} disconnected unexpectedly.")
    finally:
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        
        leave_msg = f"Server: {client_name} has left the chat.\n".encode('utf-8')
        print(leave_msg.decode('utf-8').strip())
        broadcast(leave_msg, client_socket) # Notify others
        client_socket.close()

def run_server(host='0.0.0.0', port=12345):
    """
    Starts the chat server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # This allows reusing the address, helpful for quick restarts
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
    except socket.error as e:
        print(f"Error binding to port {port}: {e}")
        sys.exit(1)

    server_socket.listen(10)
    print(f"Python Chat Server is running on port {port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            thread.daemon = True # Allows main program to exit even if threads are running
            thread.start()
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    finally:
        server_socket.close()
        print("Server has been shut down.")

if __name__ == "__main__":
    # Test cases are instructions on how to connect to this server.
    # The server needs to be run continuously to accept connections.
    print("--- Python Server Test ---")
    print("How to Test:")
    print("1. Run this Python script: python your_script_name.py")
    print("2. The server will start and print 'Python Chat Server is running...'.")
    print("3. Open 5 separate terminal/command prompt windows.")
    print("4. In each terminal, connect using telnet or netcat:")
    print("   telnet localhost 12345")
    print("5. Type messages and press Enter to chat. They will be broadcasted to all clients.")
    print("6. To quit a client, type 'exit' or close the terminal.")
    print("7. To stop the server, press Ctrl+C in the terminal where it's running.")
    print("--------------------------")
    run_server()