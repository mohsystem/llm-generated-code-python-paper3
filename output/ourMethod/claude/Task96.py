
import socket
import threading
import time
from typing import Optional

MAX_MESSAGE_SIZE = 8192
SOCKET_TIMEOUT = 30
MIN_PORT = 1024
MAX_PORT = 65535

def start_echo_server(port: int) -> None:
    if not isinstance(port, int) or port < MIN_PORT or port > MAX_PORT:
        raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}")
    
    server_socket = None
    client_socket = None
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', port))
        server_socket.listen(1)
        server_socket.settimeout(SOCKET_TIMEOUT)
        
        print(f"Server listening on port {port}")
        
        client_socket, address = server_socket.accept()
        client_socket.settimeout(SOCKET_TIMEOUT)
        
        data = client_socket.recv(MAX_MESSAGE_SIZE)
        if data:
            message = data.decode('utf-8', errors='ignore')
            if len(message) <= MAX_MESSAGE_SIZE:
                response = message.encode('utf-8')
                client_socket.sendall(response)
    
    except socket.timeout:
        print(f"Server on port {port} timed out")
    except Exception as e:
        print(f"Server error on port {port}: {e}")
    finally:
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
        if server_socket:
            try:
                server_socket.close()
            except:
                pass

def main() -> None:
    for test_case in range(1, 6):
        port = 9000 + test_case
        
        server_thread = threading.Thread(target=start_echo_server, args=(port,), daemon=True)
        server_thread.start()
        
        time.sleep(0.5)
        
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)
            client_socket.connect(('127.0.0.1', port))
            
            test_message = f"Test message {test_case}"
            client_socket.sendall(test_message.encode('utf-8'))
            
            response = client_socket.recv(MAX_MESSAGE_SIZE)
            received = response.decode('utf-8', errors='ignore')
            
            print(f"Test {test_case}: Sent='{test_message}', Received='{received}'")
        
        except Exception as e:
            print(f"Test {test_case} failed: {e}")
        finally:
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
        
        server_thread.join(timeout=2)
        time.sleep(0.2)

if __name__ == "__main__":
    main()
