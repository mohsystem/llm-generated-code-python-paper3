import socket
import threading
import sys
import time

HOST = '127.0.0.1'
PORT = 12345
MAX_MSG_LENGTH = 512

clients = []
# A lock is crucial for thread safety when modifying the shared clients list.
clients_lock = threading.Lock()

def sanitize_input(message):
    """
    Sanitizes input by removing control characters and stripping whitespace.
    This helps prevent log injection or other control-character-based attacks.
    """
    if not isinstance(message, str):
        return ""
    # Remove ASCII control characters except for tab, newline, carriage return
    sanitized = "".join(ch for ch in message if 31 < ord(ch) < 127 or ch in '\t\r\n')
    return sanitized.strip()

def broadcast(message, sender_conn):
    """
    Sends a message to all connected clients except the sender.
    """
    with clients_lock:
        for client_conn in clients:
            # We broadcast to everyone, including the sender, for chat history consistency
            try:
                client_conn.sendall(message)
            except socket.error:
                # This client has disconnected, handle removal in the client thread
                pass

def handle_client(conn, addr):
    """
    Handles a single client connection.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    
    try:
        # First message is the client's name
        name_bytes = conn.recv(1024)
        client_name = sanitize_input(name_bytes.decode('utf-8'))
        if not client_name:
            client_name = f"Anonymous@{addr[0]}"
        
        print(f"Client name is {client_name}")
        join_msg = f"{client_name} has joined the chat.".encode('utf-8')
        broadcast(join_msg, conn)

        with clients_lock:
            clients.append(conn)

        while True:
            # Input validation: receive a limited number of bytes to prevent DoS.
            message_bytes = conn.recv(MAX_MSG_LENGTH)
            if not message_bytes:
                # Empty message means client disconnected.
                break

            message_str = sanitize_input(message_bytes.decode('utf-8'))
            if message_str:
                full_message = f"{client_name}: {message_str}".encode('utf-8')
                print(f"Broadcasting from {client_name}: {message_str}")
                broadcast(full_message, conn)

    except (ConnectionResetError, UnicodeDecodeError):
        print(f"[DISCONNECTED] {addr} disconnected unexpectedly.")
    finally:
        # Resource management: ensure connection is closed and removed from list.
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        
        leave_msg = f"{client_name} has left the chat.".encode('utf-8')
        broadcast(leave_msg, conn)
        conn.close()
        print(f"[CONNECTION CLOSED] {addr} connection closed.")


def run_server():
    """
    Starts the chat server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allows reusing the address, helpful for quick restarts
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[LISTENING] Server is listening on {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            # Create a new thread for each client to handle them concurrently.
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True # Allows main thread to exit even if client threads are running
            thread.start()
    except OSError as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()
        print("Server shut down.")

def receive_messages(client_socket):
    """
    Receives messages from the server and prints them.
    """
    try:
        while True:
            message = client_socket.recv(MAX_MSG_LENGTH)
            if not message:
                print("\nDisconnected from server.")
                break
            print(message.decode('utf-8'))
    except ConnectionResetError:
        print("\nConnection to the server was lost.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

def run_client():
    """
    Starts the chat client.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Connection refused. Is the server running?")
        return

    name = input("Enter your name: ")
    client_socket.sendall(name.encode('utf-8'))

    # Start a thread to listen for incoming messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    print("Connected. You can start sending messages. Type 'exit' to quit.")
    try:
        while True:
            message = input()
            if message.lower() == 'exit':
                break
            if message:
                client_socket.sendall(message.encode('utf-8'))
    except (KeyboardInterrupt, EOFError):
        print("\nClient shutting down.")
    finally:
        client_socket.close()

def run_test_cases():
    """
    Runs an automated test suite.
    """
    print("--- Running Automated Test Cases ---")

    # Test Case 1: Start server
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.5)  # Give server time to start

    test_clients = []
    
    # Test Case 2 & 3: Two clients connect and send a message
    client_messages = {
        "ClientA": "Hello from A!",
        "ClientB": "Hi from B!"
    }

    for name, msg in client_messages.items():
        client_thread = threading.Thread(target=run_test_client, args=(name, msg))
        client_thread.start()
        test_clients.append(client_thread)
        time.sleep(0.2) # Stagger connections

    # Test Case 4: A third client connects and sends a message
    client3_thread = threading.Thread(target=run_test_client, args=("ClientC", "I'm C!"))
    client3_thread.start()
    test_clients.append(client3_thread)
    
    # Test Case 5: Wait for clients to finish
    for t in test_clients:
        t.join(timeout=3)

    print("\n--- Test Cases Finished ---")
    # The server thread is a daemon, so it will exit when the main thread does.

def run_test_client(name, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(name.encode('utf-8'))
            time.sleep(0.2)
            s.sendall(message.encode('utf-8'))
            time.sleep(0.5) # Wait to receive broadcasts
    except Exception as e:
        print(f"Test client {name} failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == 'server':
            run_server()
        elif sys.argv[1] == 'client':
            run_client()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python your_script.py [server|client]")
    else:
        run_test_cases()
        print("To run manually: python your_script.py [server|client]")