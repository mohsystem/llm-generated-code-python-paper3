import socket
import threading
from typing import Dict, List, Optional

# A simple, thread-safe remote object server.
# NOTE: This implementation does not use TLS/SSL for encrypted communication
# or any form of authentication. In a production environment, these are critical.

class RemoteObjectServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        # The shared object (a dictionary) and a lock for synchronization.
        # Rule #1: Using a lock mitigates TOCTOU vulnerabilities by ensuring
        # atomic check-and-act operations on the shared resource.
        self._remote_object: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._server_socket: Optional[socket.socket] = None
        self._running = True

    def _handle_client(self, conn: socket.socket, addr):
        print(f"Connected by {addr}")
        try:
            # Using a file-like object for easier line-by-line reading
            with conn, conn.makefile('r', encoding='utf-8') as rfile, \
                 conn.makefile('w', encoding='utf-8') as wfile:
                while self._running:
                    line = rfile.readline()
                    if not line:
                        break
                    
                    # Rule #4: Validate and sanitize all input.
                    parts = line.strip().split(" ", 2)
                    if not parts or not parts[0]:
                        continue

                    command = parts[0].upper()
                    response = self._process_command(command, parts)
                    
                    wfile.write(response + '\n')
                    wfile.flush()

                    if command == "EXIT":
                        break
        except Exception as e:
            # Rule #14: Catch and handle exceptions.
            print(f"Error handling client {addr}: {e}")
        finally:
            print(f"Connection from {addr} closed.")

    def _process_command(self, command: str, parts: List[str]) -> str:
        MAX_KEY_LENGTH = 256
        MAX_VALUE_LENGTH = 1024

        try:
            if command == "PUT":
                if len(parts) != 3:
                    return "ERROR: PUT requires 2 arguments: key and value."
                key, value = parts[1], parts[2]
                if len(key) > MAX_KEY_LENGTH or len(value) > MAX_VALUE_LENGTH:
                    return "ERROR: Key or value exceeds maximum length."
                with self._lock:
                    self._remote_object[key] = value
                return "OK"
            elif command == "GET":
                if len(parts) != 2:
                    return "ERROR: GET requires 1 argument: key."
                key = parts[1]
                if len(key) > MAX_KEY_LENGTH:
                    return "ERROR: Key exceeds maximum length."
                with self._lock:
                    value = self._remote_object.get(key)
                return f"VALUE {value}" if value is not None else "NOT_FOUND"
            elif command == "DELETE":
                if len(parts) != 2:
                    return "ERROR: DELETE requires 1 argument: key."
                key = parts[1]
                if len(key) > MAX_KEY_LENGTH:
                    return "ERROR: Key exceeds maximum length."
                with self._lock:
                    if key in self._remote_object:
                        del self._remote_object[key]
                        return "OK"
                    else:
                        return "NOT_FOUND"
            elif command == "EXIT":
                return "GOODBYE"
            else:
                # Rule #4: Reject unexpected commands.
                return f"ERROR: Unknown command '{command}'."
        except Exception:
            # Rule #14: Ensure exceptions are caught and handled.
            return "ERROR: An internal server error occurred."
    
    def start(self):
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow reusing the address to avoid "Address already in use" errors
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen()
            print(f"Server listening on {self.host}:{self.port}")
            
            while self._running:
                try:
                    conn, addr = self._server_socket.accept()
                    client_thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    if self._running:
                        print("Error accepting connection.")
                    break # Exit loop if socket is closed
            
        except Exception as e:
            if self._running:
                print(f"Server error: {e}")
        finally:
            self.stop()
            print("Server stopped.")

    def stop(self):
        self._running = False
        if self._server_socket:
            try:
                # This connection attempt will fail but will unblock the accept() call
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    s.connect((self.host, self.port))
            except socket.error:
                pass
            self._server_socket.close()
            self._server_socket = None


def send_request(host: str, port: int, request: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            # Rule #6: Send data with proper encoding and termination.
            s.sendall((request + '\n').encode('utf-8'))
            # Rule #6: Receive data with a buffer limit to prevent overflow.
            response = s.recv(4096).decode('utf-8').strip()
            return response
    except Exception as e:
        return f"CLIENT_ERROR: {e}"

def main():
    host, port = "127.0.0.1", 12346
    server = RemoteObjectServer(host, port)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()

    import time
    time.sleep(0.5)

    print("--- Running Test Cases ---")

    # Test Case 1: PUT and GET a value
    print("Test Case 1: PUT and GET")
    response1 = send_request(host, port, "PUT key1 value1")
    print(f"Client sent: PUT key1 value1 -> Server responded: {response1}")
    response2 = send_request(host, port, "GET key1")
    print(f"Client sent: GET key1 -> Server responded: {response2}")
    print()

    # Test Case 2: GET a non-existent value
    print("Test Case 2: GET non-existent key")
    response3 = send_request(host, port, "GET non_existent_key")
    print(f"Client sent: GET non_existent_key -> Server responded: {response3}")
    print()

    # Test Case 3: DELETE a value
    print("Test Case 3: DELETE a key")
    response4 = send_request(host, port, "DELETE key1")
    print(f"Client sent: DELETE key1 -> Server responded: {response4}")
    response5 = send_request(host, port, "GET key1")
    print(f"Client sent: GET key1 -> Server responded: {response5}")
    print()

    # Test Case 4: Invalid command
    print("Test Case 4: Invalid command")
    response6 = send_request(host, port, "INVALID_COMMAND")
    print(f"Client sent: INVALID_COMMAND -> Server responded: {response6}")
    print()

    # Test Case 5: Malformed command (wrong number of arguments)
    print("Test Case 5: Malformed command")
    response7 = send_request(host, port, "PUT key2")
    print(f"Client sent: PUT key2 -> Server responded: {response7}")
    print()

    server.stop()
    server_thread.join(timeout=1.0)
    print("--- Test Cases Finished ---")

if __name__ == "__main__":
    main()