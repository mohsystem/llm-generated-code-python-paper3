import socket
import threading
import sys

HOST = '127.0.0.1'
PORT = 12345
MAX_CLIENTS = 10
clients = []
client_lock = threading.Lock()

def broadcast(message, sender_socket):
    """Broadcasts a message to all clients except the sender."""
    with client_lock:
        for client_socket in clients:
            if client_socket != sender_socket:
                try:
                    client_socket.send(message)
                except:
                    # Remove the broken connection
                    client_socket.close()
                    clients.remove(client_socket)

def handle_client(client_socket):
    """Handles a single client connection."""
    try:
        # Get client name
        client_socket.send("Enter your name: ".encode('utf-8'))
        name = client_socket.recv(1024).decode('utf-8').strip()
        if not name:
            name = f"Anonymous{threading.get_ident() % 100}"
        
        print(f"{name} has connected.")
        broadcast_msg = f"{name} has joined the chat!".encode('utf-8')
        broadcast(broadcast_msg, client_socket)

        with client_lock:
            clients.append(client_socket)

        while True:
            try:
                message = client_socket.recv(1024)
                if not message or message.decode('utf-8').strip().lower() == 'exit':
                    break
                
                # Format and broadcast the message
                formatted_message = f"{name}: {message.decode('utf-8')}".encode('utf-8')
                print(f"Broadcasting from {name}: {message.decode('utf-8').strip()}")
                broadcast(formatted_message, client_socket)

            except ConnectionResetError:
                break
    
    finally:
        # Cleanup when client disconnects
        with client_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        
        print(f"{name} has disconnected.")
        broadcast(f"{name} has left the chat.".encode('utf-8'), client_socket)
        client_socket.close()


def start_server():
    """Starts the chat server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        print(f"Server started on {HOST}:{PORT}. Waiting for connections...")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.daemon = True # Allows main thread to exit even if client threads are running
            thread.start()
    except OSError as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()


def receive_messages(client_socket):
    """Listens for messages from the server."""
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(message)
            else:
                # Server has closed the connection
                print("Disconnected from the server.")
                break
        except:
            print("An error occurred. Disconnecting.")
            break
    client_socket.close()


def start_client():
    """Starts the chat client."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
        print("Connected to the chat server. Type 'exit' to quit.")

        # Handle initial name prompt
        initial_prompt = client_socket.recv(1024).decode('utf-8')
        name = input(initial_prompt)
        client_socket.send(name.encode('utf-8'))

        # Start a thread for receiving messages
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Main thread for sending messages
        while True:
            message = input()
            if message.lower() == 'exit':
                client_socket.send(message.encode('utf-8'))
                break
            client_socket.send(message.encode('utf-8'))

    except ConnectionRefusedError:
        print("Connection refused. Is the server running?")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage: python your_script_name.py <mode>")
        print("  mode: 'server' or 'client'")
        print("\n--- How to Test (5 Test Cases) ---")
        print("1. Start the server: Open a terminal and run 'python your_script_name.py server'")
        print("2. Start Client 1: Open a second terminal and run 'python your_script_name.py client'. Enter a name.")
        print("3. Start Client 2: Open a third terminal and run 'python your_script_name.py client'. Enter another name.")
        print("4. Send Messages: Type a message in Client 1's terminal and press Enter. The message should appear in Client 2's terminal, and vice-versa.")
        print("5. Client Disconnect: In Client 1's terminal, type 'exit' and press Enter. A 'has left' message should appear on the server and in Client 2's terminal.")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == 'server':
        start_server()
    elif mode == 'client':
        start_client()

if __name__ == "__main__":
    main()