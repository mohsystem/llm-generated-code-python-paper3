import socket
import threading
import sys
import hashlib
import os
import binascii

USER_FILE = "users.dat"
HOST = "127.0.0.1"
PORT = 12345
SALT_LENGTH = 16
HASH_ALGORITHM = 'sha256'
ITERATIONS = 100000

# --- Utility for Password Hashing (PBKDF2) ---
def hash_password(password, salt):
    """Hashes password with salt using PBKDF2."""
    pwd_hash = hashlib.pbkdf2_hmac(HASH_ALGORITHM, password.encode('utf-8'), salt, ITERATIONS)
    return pwd_hash

def get_salt():
    """Generates a random salt."""
    return os.urandom(SALT_LENGTH)

# --- Main function to dispatch Client, Server, or Add User ---
def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1].lower()
    if command == "server":
        server = Server()
        server.start()
    elif command == "client":
        client = Client()
        client.start()
    elif command == "adduser":
        if len(sys.argv) != 4:
            print("Usage: python your_script_name.py adduser <username> <password>")
        else:
            add_user(sys.argv[2], sys.argv[3])
    else:
        print_usage()

def print_usage():
    print("--- Secure Chat System ---")
    print("1. To add a user (run this first):")
    print("   python your_script_name.py adduser <username> <password>")
    print("\n2. To start the server:")
    print("   python your_script_name.py server")
    print("\n3. To start the client (in a new terminal):")
    print("   python your_script_name.py client")
    print("\n--- Test Cases to run on Client ---")
    print("1. Login with correct credentials.")
    print("2. Try to login with correct user, wrong password.")
    print("3. Try to login with a non-existent user.")
    print("4. Login correctly and send a message.")
    print("5. Try to login with an empty username or password.")
    
def add_user(username, password):
    if not username or not password:
        print("Username and password cannot be empty.")
        return
    try:
        with open(USER_FILE, "a") as f:
            salt = get_salt()
            hashed_pw = hash_password(password, salt)
            # Store as hex for readability in the file
            f.write(f"{username}:{binascii.hexlify(salt).decode()}:{binascii.hexlify(hashed_pw).decode()}\n")
        print(f"User '{username}' added successfully.")
    except IOError as e:
        print(f"Error adding user: {e}")

# --- Server Implementation ---
class Server:
    def __init__(self):
        self.user_credentials = {}
        self.connected_clients = {} # username -> socket
        self.load_users()

    def load_users(self):
        if not os.path.exists(USER_FILE):
            print("User file not found. Please add users first.")
            return
        try:
            with open(USER_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) == 3:
                        self.user_credentials[parts[0]] = (parts[1], parts[2]) # salt, hash
            print(f"Loaded {len(self.user_credentials)} users.")
        except IOError as e:
            print(f"Error loading user file: {e}")
            
    def broadcast(self, message, sender_socket=None):
        print(f"Broadcasting: {message}")
        for client_socket in self.connected_clients.values():
            # Optionally, don't send the message back to the sender
            # if client_socket is not sender_socket:
            try:
                client_socket.sendall(message.encode('utf-8'))
            except socket.error:
                # Client has likely disconnected, handle later
                pass
                
    def handle_client(self, client_socket):
        username = None
        try:
            username = self.authenticate(client_socket)
            if username:
                print(f"User '{username}' authenticated successfully.")
                self.connected_clients[username] = client_socket
                self.broadcast(f"\nSERVER: {username} has joined the chat.\n")
                
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break # Client disconnected
                    message = data.decode('utf-8').strip()
                    if message.upper() == 'LOGOUT':
                        break
                    self.broadcast(f"{username}: {message}\n")
            else:
                print("Authentication failed.")
        except socket.error as e:
            print(f"Socket error with a client: {e}")
        finally:
            if username and username in self.connected_clients:
                del self.connected_clients[username]
                self.broadcast(f"\nSERVER: {username} has left the chat.\n")
            client_socket.close()

    def authenticate(self, client_socket):
        try:
            client_socket.sendall(b"SUBMIT_credentials\n")
            data = client_socket.recv(1024).decode('utf-8').strip()
            
            if not data.startswith("LOGIN "):
                client_socket.sendall(b"LOGIN_FAIL Invalid request format.\n")
                return None
            
            parts = data.split(" ", 2)
            if len(parts) != 3:
                client_socket.sendall(b"LOGIN_FAIL Invalid credentials format.\n")
                return None
            
            username, password = parts[1], parts[2]
            
            if username not in self.user_credentials:
                client_socket.sendall(b"LOGIN_FAIL Invalid username or password.\n")
                return None
            
            stored_salt_hex, stored_hash_hex = self.user_credentials[username]
            stored_salt = binascii.unhexlify(stored_salt_hex)
            stored_hash = binascii.unhexlify(stored_hash_hex)

            provided_hash = hash_password(password, stored_salt)
            
            if provided_hash == stored_hash:
                client_socket.sendall(b"LOGIN_SUCCESS\n")
                return username
            else:
                client_socket.sendall(b"LOGIN_FAIL Invalid username or password.\n")
                return None

        except (socket.error, IndexError):
            return None

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server started on {HOST}:{PORT}")
        
        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Accepted connection from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server.")
        finally:
            server_socket.close()
            
# --- Client Implementation ---
class Client:
    def receive_messages(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    print("\nConnection to server lost.")
                    break
                sys.stdout.write(message)
                sys.stdout.flush()
            except socket.error:
                print("\nAn error occurred. Disconnecting.")
                break
        os._exit(0) # Exit forcefully to stop the input loop

    def start(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((HOST, PORT))
            print("Connected to server.")

            response = client_socket.recv(1024).decode('utf-8').strip()
            if response == "SUBMIT_credentials":
                username = input("Enter username: ")
                password = input("Enter password: ")

                client_socket.sendall(f"LOGIN {username} {password}\n".encode('utf-8'))
                
                login_response = client_socket.recv(1024).decode('utf-8').strip()
                print(f"Server: {login_response}")
                
                if login_response == "LOGIN_SUCCESS":
                    print("Login successful! You can now chat. Type 'LOGOUT' to exit.")
                    
                    receive_thread = threading.Thread(target=self.receive_messages, args=(client_socket,))
                    receive_thread.daemon = True
                    receive_thread.start()
                    
                    while True:
                        message = sys.stdin.readline().strip()
                        if message.upper() == 'LOGOUT':
                            client_socket.sendall(b'LOGOUT\n')
                            break
                        client_socket.sendall((message + '\n').encode('utf-8'))
            
        except (socket.error, ConnectionRefusedError) as e:
            print(f"Client error: {e}")
        finally:
            client_socket.close()
            print("Connection closed.")

if __name__ == "__main__":
    main()