import socket
import threading
import time

HOST = '127.0.0.1'
PORT = 12345
clients = []
clients_lock = threading.Lock()
server_running = True

def broadcast(message, sender_conn):
    """Broadcasts a message to all clients except the sender."""
    with clients_lock:
        print(f"Broadcasting: {message.decode('utf-8')}")
        for client_conn in clients:
            if client_conn != sender_conn:
                try:
                    client_conn.sendall(message)
                except socket.error:
                    # Client might have disconnected, will be removed soon
                    pass

def handle_client(conn, addr):
    """Handles a single client connection."""
    client_name = f"Client-{addr[1]}"
    print(f"{client_name} connected.")
    broadcast(f"{client_name} has joined the chat.\n".encode('utf-8'), conn)
    
    with conn:
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message_to_broadcast = f"{client_name}: {data.decode('utf-8')}\n".encode('utf-8')
                broadcast(message_to_broadcast, conn)
        except (ConnectionResetError, BrokenPipeError):
            pass # Client disconnected abruptly
        finally:
            with clients_lock:
                if conn in clients:
                    clients.remove(conn)
            broadcast(f"{client_name} has left the chat.\n".encode('utf-8'), conn)
            print(f"{client_name} disconnected.")

def server_thread():
    """Main server thread to accept connections."""
    global server_running
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, PORT))
            s.listen()
            s.settimeout(1.0) # Timeout to check server_running flag
            print(f"Server started on {HOST}:{PORT}")
            while server_running:
                try:
                    conn, addr = s.accept()
                    with clients_lock:
                        clients.append(conn)
                    thread = threading.Thread(target=handle_client, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
        except OSError as e:
            print(f"Server error: {e}")
        finally:
            print("Server shutting down.")
            with clients_lock:
                for conn in clients:
                    conn.close()

def client_thread(client_id, messages):
    """Simulates a single client."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # Listener thread for this client
            def listen_for_messages(sock):
                while True:
                    try:
                        response = sock.recv(1024)
                        if not response:
                            break
                        print(f"Client-{client_id} received: {response.decode('utf-8').strip()}")
                    except (ConnectionResetError, ConnectionAbortedError):
                        break
            
            listener = threading.Thread(target=listen_for_messages, args=(s,))
            listener.daemon = True
            listener.start()

            for msg in messages:
                s.sendall(msg.encode('utf-8'))
                time.sleep(0.5 + (client_id * 0.1))
            
            time.sleep(1) # Wait for final messages
            s.close()

    except ConnectionRefusedError:
        print(f"Client-{client_id}: Connection refused. Is the server running?")
    except Exception as e:
        print(f"Client-{client_id} error: {e}")
    finally:
        print(f"Client-{client_id} finished.")

def main():
    """Main function to run the simulation."""
    global server_running
    
    # Start the server in a separate thread
    s_thread = threading.Thread(target=server_thread)
    s_thread.start()
    time.sleep(1) # Give server time to start

    # Test cases: 5 clients
    client_messages = [
        ["Hello everyone!"],
        ["Hi from client 2!", "How is it going?"],
        ["Good morning."],
        ["Just testing."],
        ["Final client here!", "See ya!"]
    ]
    
    client_threads = []
    for i in range(5):
        ct = threading.Thread(target=client_thread, args=(i + 1, client_messages[i]))
        client_threads.append(ct)
        ct.start()
    
    # Wait for all client threads to complete
    for ct in client_threads:
        ct.join()

    print("All clients are done. Stopping server...")
    server_running = False
    s_thread.join()
    print("Chat simulation finished.")

if __name__ == "__main__":
    main()