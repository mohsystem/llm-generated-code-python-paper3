
import socket
import sys
import threading

BUFFER_SIZE = 8192
TIMEOUT_SEC = 30
MIN_PORT = 1024
MAX_PORT = 65535

def start_server(port):
    """Start the echo server on specified port"""
    if port < MIN_PORT or port > MAX_PORT:
        print(f"Port must be between {MIN_PORT} and {MAX_PORT}", file=sys.stderr)
        return
    
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(TIMEOUT_SEC)
        server_socket.bind(('localhost', port))
        server_socket.listen(5)
        print(f"Server listening on port {port}")
        
        while True:
            client_socket = None
            try:
                client_socket, address = server_socket.accept()
                client_socket.settimeout(TIMEOUT_SEC)
                print(f"Client connected: {address}")
                handle_client(client_socket)
            except socket.timeout:
                print("Accept timeout, continuing...")
            except Exception as e:
                print(f"Error handling client: {e}", file=sys.stderr)
            finally:
                if client_socket:
                    try:
                        client_socket.close()
                    except Exception as e:
                        print(f"Error closing client socket: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
    finally:
        if server_socket:
            try:
                server_socket.close()
            except Exception as e:
                print(f"Error closing server socket: {e}", file=sys.stderr)

def handle_client(client_socket):
    """Handle client communication"""
    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break
            
            message = data.decode('utf-8', errors='replace')
            if len(message) > BUFFER_SIZE:
                message = message[:BUFFER_SIZE]
            
            print(f"Received: {message.strip()}")
            client_socket.sendall(data)
    except Exception as e:
        print(f"Client communication error: {e}", file=sys.stderr)

def test_client(port, message, test_num):
    """Test client connection"""
    print(f"\\nTest {test_num}: Sending message: {message}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(5)
            client_socket.connect(('localhost', port))
            client_socket.sendall((message + '\\n').encode('utf-8'))
            response = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='replace')
            print(f"Response: {response.strip()}")
    except Exception as e:
        print(f"Client test error: {e}", file=sys.stderr)

if __name__ == "__main__":
    # Test 1: Start server
    print("Test 1: Starting echo server on port 8080")
    server_thread = threading.Thread(target=start_server, args=(8080,), daemon=True)
    server_thread.start()
    
    # Give server time to start
    import time
    time.sleep(1)
    
    # Test cases with client connections
    test_messages = [
        "Hello, Server!",
        "Echo test message",
        "Test 123",
        "Special chars: @#$%",
        "Final test message"
    ]
    
    for i, msg in enumerate(test_messages, start=2):
        test_client(8080, msg, i)
        time.sleep(0.5)
    
    time.sleep(1)
