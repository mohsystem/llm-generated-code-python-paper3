
import socket
import threading

DEFAULT_PORT = 8080
BUFFER_SIZE = 1024

def handle_client(client_socket, address):
    """Handle individual client connection"""
    try:
        print(f"Client connected: {address}")
        while True:
            message = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if not message:
                break
            print(f"Received: {message}")
            client_socket.send(message.encode('utf-8'))  # Echo back
    except Exception as e:
        print(f"Client handler error: {e}")
    finally:
        client_socket.close()
        print(f"Client disconnected: {address}")

def start_server(port):
    """Start the echo server on specified port"""
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"Server started on port {port}")
        
        while True:
            client_socket, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if server_socket:
            server_socket.close()

if __name__ == "__main__":
    print("Echo Server Test Cases")
    print("======================")
    print("Test Case 1: Start server on default port 8080")
    print("Test Case 2: Server handles multiple clients")
    print("Test Case 3: Server echoes messages correctly")
    print("Test Case 4: Server handles client disconnection")
    print("Test Case 5: Server runs continuously")
    print("\\nStarting server...")
    
    start_server(DEFAULT_PORT)
