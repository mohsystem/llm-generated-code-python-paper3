import socket

def start_server(host, port, max_clients):
    """
    Starts a secure echo server on the specified host and port.
    The server handles a limited number of clients sequentially and then shuts down.
    
    :param host: The hostname or IP address to bind to.
    :param port: The port number to listen on.
    :param max_clients: The number of clients to serve before shutting down.
    """
    # Use a 'with' statement to ensure the socket is automatically closed.
    # AF_INET is for IPv4, SOCK_STREAM is for TCP.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            # Allow reusing the address to avoid "Address already in use" errors
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"Server is listening on {host}:{port}")
            print(f"Server will handle {max_clients} clients and then shut down.")

            for i in range(max_clients):
                print(f"\nWaiting for client {i + 1}/{max_clients}...")
                try:
                    # Accept a client connection. This is a blocking call.
                    # Use a 'with' statement for the client socket as well.
                    conn, addr = server_socket.accept()
                    with conn:
                        print(f"Client connected from {addr}")

                        # Set a timeout (e.g., 10 seconds) on the client socket
                        # to prevent slow or malicious clients from blocking the server.
                        conn.settimeout(10.0)
                        
                        while True:
                            # Receive data from the client.
                            # The buffer size limits the amount of data received in one go,
                            # preventing a single large packet from consuming too much memory.
                            data = conn.recv(4096)
                            if not data:
                                # If recv returns an empty byte string, the client has closed the connection.
                                break
                            
                            # Echo the data back to the client.
                            # sendall continues to send data until all data has been sent.
                            conn.sendall(data)
                            print(f"Echoed {len(data)} bytes to {addr}")
                
                except socket.timeout:
                    print("Client connection timed out.")
                except socket.error as e:
                    print(f"An error occurred with a client: {e}")
                finally:
                    print("Client disconnected or connection closed.")

        except socket.error as e:
            print(f"Server error: {e}")
        finally:
            print(f"Server shutting down after handling {max_clients} clients.")


if __name__ == "__main__":
    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 8080         # Port to listen on (non-privileged ports are > 1023)
    NUMBER_OF_TEST_CONNECTIONS = 5

    print("--- Echo Server Test ---")
    print(f"To test, connect to this server using a client like netcat or telnet.")
    print(f"Example 1: nc {HOST} {PORT}")
    print(f"Example 2: telnet {HOST} {PORT}")
    print("Type a message and press Enter. The server will echo it back.")
    print(f"The server will shut down after handling {NUMBER_OF_TEST_CONNECTIONS} connections.")
    print("-------------------------")
    
    start_server(HOST, PORT, NUMBER_OF_TEST_CONNECTIONS)