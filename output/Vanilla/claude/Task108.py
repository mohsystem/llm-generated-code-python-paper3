
import socket
import threading
import json
from typing import Any, Dict, Set

object_store: Dict[str, Any] = {}
store_lock = threading.Lock()

def store_object(key: str, value: Any) -> None:
    with store_lock:
        object_store[key] = value

def retrieve_object(key: str) -> Any:
    with store_lock:
        return object_store.get(key)

def delete_object(key: str) -> bool:
    with store_lock:
        if key in object_store:
            del object_store[key]
            return True
        return False

def list_keys() -> Set[str]:
    with store_lock:
        return set(object_store.keys())

def handle_client(client_socket):
    try:
        request = client_socket.recv(4096).decode('utf-8')
        if not request:
            return
        
        parts = request.split('|')
        command = parts[0]
        response = ""
        
        if command == "STORE" and len(parts) >= 3:
            store_object(parts[1], parts[2])
            response = "OK|Object stored"
        elif command == "RETRIEVE" and len(parts) >= 2:
            value = retrieve_object(parts[1])
            response = f"OK|{value}" if value is not None else "ERROR|Key not found"
        elif command == "DELETE" and len(parts) >= 2:
            deleted = delete_object(parts[1])
            response = "OK|Object deleted" if deleted else "ERROR|Key not found"
        elif command == "LIST":
            response = f"OK|{list_keys()}"
        else:
            response = "ERROR|Unknown command or invalid parameters"
        
        client_socket.send(response.encode('utf-8'))
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_server(port: int) -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Server listening on port {port}")
    
    while True:
        client_socket, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

def main():
    # Test cases
    print("=== Test Case 1: Store and Retrieve ===")
    store_object("key1", "Hello World")
    print(f"Retrieved: {retrieve_object('key1')}")
    
    print("\\n=== Test Case 2: Store Multiple Objects ===")
    store_object("key2", 12345)
    store_object("key3", [1.1, 2.2, 3.3])
    print(f"Retrieved key2: {retrieve_object('key2')}")
    print(f"Retrieved key3: {retrieve_object('key3')}")
    
    print("\\n=== Test Case 3: Update Object ===")
    store_object("key1", "Updated Value")
    print(f"Updated key1: {retrieve_object('key1')}")
    
    print("\\n=== Test Case 4: Delete Object ===")
    deleted = delete_object("key2")
    print(f"Deleted key2: {deleted}")
    print(f"Retrieve deleted key2: {retrieve_object('key2')}")
    
    print("\\n=== Test Case 5: List All Keys ===")
    print(f"All keys: {list_keys()}")
    
    # Start server in a separate thread for demonstration
    server_thread = threading.Thread(target=start_server, args=(8080,))
    server_thread.daemon = True
    server_thread.start()
    
    print("\\nServer started on port 8080. Press Ctrl+C to stop.")
    
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\\nShutting down...")

if __name__ == "__main__":
    main()
