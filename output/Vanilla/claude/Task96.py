
import socket
import threading
import time

class Task96:
    PORT = 8888
    
    @staticmethod
    def start_server(port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('localhost', port))
            server_socket.listen(5)
            print(f"Server started on port {port}")
            
            while True:
                try:
                    client_socket, address = server_socket.accept()
                    print(f"Client connected: {address}")
                    
                    while True:
                        data = client_socket.recv(1024).decode('utf-8')
                        if not data:
                            break
                        
                        print(f"Received: {data.strip()}")
                        client_socket.send(data.encode('utf-8'))
                        
                        if data.strip().upper() == "QUIT":
                            break
                    
                    client_socket.close()
                    print("Client disconnected")
                except Exception as e:
                    print(f"Error handling client: {e}")
        except Exception as e:
            print(f"Could not start server: {e}")
        finally:
            server_socket.close()
    
    @staticmethod
    def send_message(port, message):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', port))
            
            client_socket.send((message + '\\n').encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8').strip()
            
            client_socket.close()
            return response
        except Exception as e:
            return f"Error: {e}"

def main():
    # Start server in a separate thread
    server_thread = threading.Thread(target=Task96.start_server, args=(Task96.PORT,), daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Test cases
    print("\\n=== Running Test Cases ===\\n")
    
    # Test 1: Simple message
    print("Test 1: Simple message")
    response1 = Task96.send_message(Task96.PORT, "Hello, Server!")
    print("Sent: Hello, Server!")
    print(f"Echo: {response1}")
    print()
    
    # Test 2: Numeric message
    print("Test 2: Numeric message")
    response2 = Task96.send_message(Task96.PORT, "12345")
    print("Sent: 12345")
    print(f"Echo: {response2}")
    print()
    
    # Test 3: Special characters
    print("Test 3: Special characters")
    response3 = Task96.send_message(Task96.PORT, "Test@#$%^&*()")
    print("Sent: Test@#$%^&*()")
    print(f"Echo: {response3}")
    print()
    
    # Test 4: Space message
    print("Test 4: Space message")
    response4 = Task96.send_message(Task96.PORT, " ")
    print("Sent: ' '")
    print(f"Echo: '{response4}'")
    print()
    
    # Test 5: Long message
    print("Test 5: Long message")
    long_msg = "This is a longer message to test the echo functionality!"
    response5 = Task96.send_message(Task96.PORT, long_msg)
    print(f"Sent: {long_msg}")
    print(f"Echo: {response5}")
    print()
    
    print("=== All Tests Completed ===")

if __name__ == "__main__":
    main()
