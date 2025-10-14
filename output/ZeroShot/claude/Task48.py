
import socket
import threading
import sys

class Task48:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.clients = []
        self.clients_lock = threading.Lock()
        
    class ClientHandler(threading.Thread):
        def __init__(self, client_socket, address, server):
            threading.Thread.__init__(self)
            self.client_socket = client_socket
            self.address = address
            self.server = server
            self.client_name = "Anonymous"
            
        def run(self):
            try:
                # Get client name
                self.client_socket.send(b"Enter your name: ")
                self.client_name = self.client_socket.recv(1024).decode('utf-8').strip()
                
                if not self.client_name:
                    self.client_name = "Anonymous"
                
                with self.server.clients_lock:
                    self.server.clients.append(self)
                
                self.server.broadcast(f"{self.client_name} has joined the chat!", self)
                
                while True:
                    message = self.client_socket.recv(1024).decode('utf-8').strip()
                    if not message or message.lower() == '/quit':
                        break
                    self.server.broadcast(f"{self.client_name}: {message}", self)
                    
            except Exception as e:
                print(f"Error handling client: {e}")
            finally:
                self.cleanup()
                
        def cleanup(self):
            with self.server.clients_lock:
                if self in self.server.clients:
                    self.server.clients.remove(self)
            self.server.broadcast(f"{self.client_name} has left the chat!", self)
            self.client_socket.close()
            
        def send_message(self, message):
            try:
                self.client_socket.send((message + '\\n').encode('utf-8'))
            except:
                pass
    
    def broadcast(self, message, sender):
        print(message)
        with self.clients_lock:
            for client in self.clients:
                client.send_message(message)
    
    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Chat server started on {self.host}:{self.port}")
            
            while True:
                client_socket, address = server_socket.accept()
                print(f"New client connected: {address}")
                handler = self.ClientHandler(client_socket, address, self)
                handler.start()
                
        except KeyboardInterrupt:
            print("\\nServer shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server_socket.close()

def main():
    print("=== Chat Server Application ===")
    print("Test Case 1: Starting server on port 8888")
    
    server = Task48(host='localhost', port=8888)
    
    # Start server in a separate thread for demonstration
    server_thread = threading.Thread(target=server.start_server)
    server_thread.daemon = True
    server_thread.start()
    
    print("\\nTo test this application:")
    print("1. Run this server")
    print("2. Use telnet or netcat to connect: telnet localhost 8888")
    print("3. Connect multiple clients and send messages")
    print("4. Type /quit to disconnect")
    print("\\nPress Ctrl+C to stop the server")
    
    # Test Cases:
    # 1. Start server - Server should listen on specified port
    # 2. Connect client 1 - Should join and receive welcome message
    # 3. Connect client 2 - Both clients should see join notification
    # 4. Client 1 sends message - All clients should receive broadcast
    # 5. Client disconnects - All clients should see leave notification
    
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\\nShutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()
