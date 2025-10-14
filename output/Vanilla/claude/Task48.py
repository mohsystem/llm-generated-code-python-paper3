
import socket
import threading
import time

class Task48:
    PORT = 12345
    clients = []
    clients_lock = threading.Lock()
    
    class ClientHandler:
        def __init__(self, client_socket, address):
            self.socket = client_socket
            self.address = address
            self.client_name = None
            
        def handle(self):
            try:
                self.socket.send(b"Enter your name:\\n")
                self.client_name = self.socket.recv(1024).decode().strip()
                Task48.broadcast(f"{self.client_name} has joined the chat!")
                
                while True:
                    message = self.socket.recv(1024).decode().strip()
                    if not message or message.lower() == "/quit":
                        break
                    Task48.broadcast(f"{self.client_name}: {message}")
            except Exception as e:
                print(f"Error handling client: {e}")
            finally:
                self.cleanup()
                
        def cleanup(self):
            with Task48.clients_lock:
                if self in Task48.clients:
                    Task48.clients.remove(self)
            if self.client_name:
                Task48.broadcast(f"{self.client_name} has left the chat!")
            self.socket.close()
            
        def send_message(self, message):
            try:
                self.socket.send((message + "\\n").encode())
            except:
                pass
    
    @staticmethod
    def broadcast(message):
        print(f"[Server] {message}")
        with Task48.clients_lock:
            for client in Task48.clients[:]:
                client.send_message(message)
    
    @staticmethod
    def start_server():
        print(f"Chat server starting on port {Task48.PORT}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', Task48.PORT))
        server_socket.listen(5)
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                handler = Task48.ClientHandler(client_socket, address)
                with Task48.clients_lock:
                    Task48.clients.append(handler)
                thread = threading.Thread(target=handler.handle)
                thread.daemon = True
                thread.start()
            except Exception as e:
                print(f"Server error: {e}")
                break
    
    class ChatClient:
        def __init__(self):
            self.socket = None
            self.running = False
            
        def connect(self, host, port, name):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.running = True
            
            welcome = self.socket.recv(1024).decode()
            print(welcome.strip())
            self.socket.send((name + "\\n").encode())
            
            def receive_messages():
                while self.running:
                    try:
                        message = self.socket.recv(1024).decode()
                        if message:
                            print(message.strip())
                        else:
                            break
                    except:
                        break
                        
            thread = threading.Thread(target=receive_messages)
            thread.daemon = True
            thread.start()
            
        def send_message(self, message):
            if self.socket:
                self.socket.send((message + "\\n").encode())
                
        def disconnect(self):
            self.running = False
            if self.socket:
                self.socket.close()

def main():
    server_thread = threading.Thread(target=Task48.start_server)
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1)
    
    try:
        print("\\n=== Test Case 1: Single client connection ===")
        client1 = Task48.ChatClient()
        client1.connect('localhost', Task48.PORT, 'Alice')
        time.sleep(0.5)
        client1.send_message('Hello from Alice!')
        time.sleep(0.5)
        
        print("\\n=== Test Case 2: Multiple clients ===")
        client2 = Task48.ChatClient()
        client2.connect('localhost', Task48.PORT, 'Bob')
        time.sleep(0.5)
        client2.send_message('Hi everyone from Bob!')
        time.sleep(0.5)
        
        print("\\n=== Test Case 3: Broadcasting ===")
        client1.send_message('This is Alice speaking')
        time.sleep(0.5)
        client2.send_message('Bob here too')
        time.sleep(0.5)
        
        print("\\n=== Test Case 4: Third client joins ===")
        client3 = Task48.ChatClient()
        client3.connect('localhost', Task48.PORT, 'Charlie')
        time.sleep(0.5)
        client3.send_message('Charlie joined the chat')
        time.sleep(0.5)
        
        print("\\n=== Test Case 5: Client disconnection ===")
        client1.send_message('/quit')
        time.sleep(0.5)
        client2.send_message('Alice left')
        time.sleep(0.5)
        
        client2.disconnect()
        client3.disconnect()
        time.sleep(1)
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
