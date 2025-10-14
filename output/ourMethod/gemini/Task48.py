import socket
import threading
import sys

HOST = '127.0.0.1'
PORT = 12345
MAX_MSG_SIZE = 1024

clients = []
clients_lock = threading.Lock()
running = True

def broadcast(message, sender_conn):
    """Broadcasts a message to all clients except the sender."""
    with clients_lock:
        for client_conn in clients:
            # Rule #1: Check and use of resource is atomic due to the lock
            if client_conn != sender_conn:
                try:
                    client_conn.sendall(message)
                except socket.error:
                    # Client might have disconnected, will be handled by its thread
                    pass

def handle_client(conn, addr):
    """Handles a single client connection."""
    print(f"[NEW CONNECTION] {addr} connected.")
    
    with clients_lock:
        clients.append(conn)

    try:
        while True:
            # Rule #6: Read at most MAX_MSG_SIZE bytes
            data = conn.recv(MAX_MSG_SIZE)
            if not data:
                break  # Client disconnected
            
            # Rule #4: Basic input validation (length already limited by recv)
            print(f"[{addr}] {data.decode('utf-8')}")
            broadcast(f"[{addr[0]}:{addr[1]}] ".encode('utf-8') + data, conn)
    except ConnectionResetError:
        print(f"[DISCONNECTED] {addr} disconnected abruptly.")
    except Exception as e:
        # Rule #9: Catch and handle exceptions
        print(f"[ERROR] {e}")
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")

def run_server():
    """Starts the chat server."""
    global running
    print("[STARTING] Server is starting...")
    # Use with statement for automatic socket closing
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Allow reusing address
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((HOST, PORT))
            server_socket.listen()
            print(f"[LISTENING] Server is listening on {HOST}:{PORT}")
        except socket.error as e:
            print(f"Server failed to start: {e}")
            return

        while running:
            try:
                conn, addr = server_socket.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.daemon = True # Allows main thread to exit even if clients are connected
                thread.start()
            except socket.error:
                break # Server socket closed

def receive_messages(sock, stop_event):
    """Receives messages from the server."""
    while not stop_event.is_set():
        try:
            # Rule #6: Read at most MAX_MSG_SIZE bytes
            message = sock.recv(MAX_MSG_SIZE)
            if not message:
                print("\nConnection to server lost.")
                stop_event.set()
                break
            print(message.decode('utf-8'))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            if not stop_event.is_set():
                print("\nDisconnected from the server.")
            stop_event.set()
            break

def run_client():
    """Starts the chat client."""
    stop_event = threading.Event()
    # Use with statement for automatic socket closing
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            print("Connected to server. Type messages and press Enter. Type 'exit' to quit.")

            receiver_thread = threading.Thread(target=receive_messages, args=(client_socket, stop_event))
            receiver_thread.daemon = True
            receiver_thread.start()

            while not stop_event.is_set():
                try:
                    message = sys.stdin.readline().strip()
                    if stop_event.is_set() or message.lower() == 'exit':
                        break
                    if message:
                        # Rule #4: Input length is implicitly validated by readline buffer, but
                        # a check before sending is good practice.
                        if len(message.encode('utf-8')) > MAX_MSG_SIZE:
                            print(f"Message too long, limit is {MAX_MSG_SIZE} bytes.")
                            continue
                        client_socket.sendall(message.encode('utf-8'))
                except KeyboardInterrupt:
                    break
    except ConnectionRefusedError:
        print("Connection refused. Is the server running?")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        stop_event.set()
        print("Disconnected.")

def main():
    """Main function to run server or client."""
    if len(sys.argv) < 2:
        print("Usage: python your_script_name.py [server|client]")
        print("\n--- Test Plan ---")
        print("1. Run 'python your_script_name.py server' in one terminal.")
        print("2. Run 'python your_script_name.py client' in a second terminal.")
        print("3. Run 'python your_script_name.py client' in a third terminal.")
        print("4. In the second terminal, type 'Hello everyone!' and press Enter. Observe the third terminal receiving the message.")
        print("5. In the third terminal, type 'Hi back!' and press Enter. Observe the second terminal receiving the message.")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == 'server':
        run_server()
    elif mode == 'client':
        run_client()
    else:
        print("Invalid mode. Use 'server' or 'client'.")
        sys.exit(1)

if __name__ == "__main__":
    main()