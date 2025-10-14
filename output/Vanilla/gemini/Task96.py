import socket
import threading

def handle_client(client_socket, addr):
    """
    Handles a single client connection, echoing back messages.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            # Receive data from the client (up to 1024 bytes)
            data = client_socket.recv(1024)
            # If recv returns an empty bytes object, the client has closed the connection
            if not data:
                break
            message = data.decode('utf-8')
            print(f"Received from {addr}: {message.strip()}")
            # Echo the data back to the client
            client_socket.sendall(data)
    except ConnectionResetError:
        print(f"[CONNECTION RESET] {addr} disconnected abruptly.")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()
        print(f"[DISCONNECTED] {addr} disconnected.")

def start_server(host, port):
    """
    Starts the echo server and listens for incoming connections.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
        server.listen(5) # Listen for up to 5 connections in the queue
        print(f"[LISTENING] Server is listening on {host}:{port}")

        while True:
            # Accept a new connection. This is a blocking call.
            client_sock, client_addr = server.accept()
            # Create a new thread to handle the client connection
            thread = threading.Thread(target=handle_client, args=(client_sock, client_addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    except OSError as e:
        print(f"[SERVER ERROR] {e}")
    finally:
        server.close()
        print("[SERVER SHUTDOWN]")


if __name__ == "__main__":
    # --- Test Cases ---
    # The server will run indefinitely. To test, you need a client program
    # or a tool like `telnet` or `netcat`.
    #
    # How to test (5 test cases):
    # 1. Run this Python program.
    # 2. Open a new terminal/command prompt.
    # 3. Test Case 1: Connect using netcat: `nc localhost 12345` or telnet: `telnet localhost 12345`
    # 4. Test Case 2: Type "Hello Python Server" and press Enter. The server should echo it back.
    # 5. Test Case 3: Type "Testing concurrency" and press Enter.
    # 6. Test Case 4: Open another new terminal and connect again: `nc localhost 12345`.
    #    Send a message from this new client. The server handles multiple clients.
    # 7. Test Case 5: Close one of the nc/telnet sessions (Ctrl+C or Ctrl+D).
    #    The other session should remain active.

    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 12345        # Port to listen on (non-privileged ports are > 1023)
    start_server(HOST, PORT)