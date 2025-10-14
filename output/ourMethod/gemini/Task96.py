import socket
from typing import Tuple

def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """Handles a single client connection, echoing back received data."""
    print(f"Client connected: {addr}")
    try:
        # Use a context manager to ensure the connection is closed.
        with conn:
            while True:
                # Read up to a fixed buffer size.
                data = conn.recv(1024)
                if not data:
                    # Client closed the connection if data is an empty bytes object.
                    break
                # Echo the data back to the client.
                conn.sendall(data)
                # For demonstration, print the received message.
                try:
                    # Use repr() for a safe representation of the received bytes.
                    print(f"Received from {addr}: {data!r}")
                except Exception as e:
                    print(f"Error decoding data from {addr}: {e}")
    except socket.error as e:
        print(f"Socket error with client {addr}: {e}")
    finally:
        print(f"Client disconnected: {addr}")


def run_server(host: str, port: int) -> None:
    """Starts the echo server."""
    try:
        # Use a context manager for the server socket.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Set socket option to reuse the address, useful for quick restarts.
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"Server is listening on {host}:{port}")

            # The server runs indefinitely, accepting one client at a time.
            while True:
                try:
                    # accept() is a blocking call.
                    conn, addr = server_socket.accept()
                    handle_client(conn, addr)
                except socket.error as e:
                    print(f"Error accepting connection: {e}")
    except socket.error as e:
        print(f"Failed to start server on {host}:{port}: {e}")
    except KeyboardInterrupt:
        print("\nServer shutting down.")


def main() -> None:
    """Main function to run the server."""
    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 8080         # Port to listen on

    print("Starting the echo server...")
    # The prompt asks for 5 test cases. A server runs continuously.
    # To test, you can use a client like netcat (nc) or telnet from 5 different
    # terminals, or sequentially after each one disconnects.
    #
    # Example test cases using netcat from a terminal:
    # Test Case 1: echo "Hello Server" | nc 127.0.0.1 8080
    # Test Case 2: echo "This is a test" | nc 127.0.0.1 8080
    # Test Case 3: echo "Another line" | nc 127.0.0.1 8080
    # Test Case 4: echo "A short one" | nc 127.0.0.1 8080
    # Test Case 5: echo "Final test message" | nc 127.0.0.1 8080
    
    run_server(HOST, PORT)

if __name__ == '__main__':
    main()