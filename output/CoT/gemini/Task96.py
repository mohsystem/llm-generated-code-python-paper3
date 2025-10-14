import socket
import threading
import time

def start_echo_server(host, port, server_event):
    """
    Starts an echo server that handles one client connection and then stops.
    """
    # Use a with statement to ensure the socket is closed automatically
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            # Set SO_REUSEADDR to allow immediate reuse of the port
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"Server is listening on {host}:{port}")
            server_event.set() # Signal that the server is ready

            # Accept one connection
            conn, addr = server_socket.accept()
            with conn:
                print(f"Client connected from {addr}")
                while True:
                    # Receive data in a loop, max 1024 bytes at a time
                    data = conn.recv(1024)
                    if not data:
                        # Client closed the connection
                        break
                    print(f"Server received: {data.decode('utf-8')}")
                    # Echo the data back to the client
                    conn.sendall(data)
                    print(f"Server echoed: {data.decode('utf-8')}")
        except OSError as e:
            print(f"Server error: {e}")
        finally:
            print("Server has shut down.")

def run_client_tests(host, port):
    """
    Connects to the server and runs 5 test cases.
    """
    test_messages = [
        "Hello, Server!",
        "This is test case 2.",
        "A message with numbers 12345.",
        "Another test.",
        "Goodbye!"
    ]
    
    try:
        # Use a with statement for the client socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            print("\nClient connected to server. Running tests...")
            
            for message in test_messages:
                # Add a newline because the server might read line by line
                message_with_newline = message + '\n'
                print(f"Client sending: {message}")
                client_socket.sendall(message_with_newline.encode('utf-8'))
                
                # Receive the echo, assuming message is not larger than buffer
                response = client_socket.recv(1024)
                print(f"Client received echo: {response.decode('utf-8').strip()}")
                
    except ConnectionRefusedError:
        print("Client error: Connection refused. Is the server running?")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        print("Client tests finished.")

if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 12346

    server_ready_event = threading.Event()

    # Start the server in a separate thread
    server_thread = threading.Thread(
        target=start_echo_server, 
        args=(HOST, PORT, server_ready_event)
    )
    server_thread.start()

    # Wait until the server signals that it's ready
    server_ready_event.wait()

    # Run client tests
    run_client_tests(HOST, PORT)

    # Wait for the server thread to complete
    server_thread.join()
    
    print("\nProgram finished.")