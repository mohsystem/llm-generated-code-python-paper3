import socket
import threading
import sys
import os
import hashlib
import base64
import getpass

USER_FILE = "users.dat"
HOST = "127.0.0.1"
PORT = 8081

# --- Security Utilities ---
def get_salt():
    return os.urandom(16)

def hash_password(password, salt):
    pwd_bytes = password.encode('utf-8')
    salted_pwd = salt + pwd_bytes
    return hashlib.sha256(salted_pwd).hexdigest()

def verify_password(password, stored_hash, salt_b64):
    salt = base64.b64decode(salt_b64)
    return hash_password(password, salt) == stored_hash

def user_exists(username):
    if not os.path.exists(USER_FILE):
        return False
    with open(USER_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if parts[0] == username:
                return True
    return False

def add_user(username, password):
    if user_exists(username):
        print(f"Error: User '{username}' already exists.")
        return
    salt = get_salt()
    hashed_pwd = hash_password(password, salt)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    with open(USER_FILE, 'a') as f:
        f.write(f"{username}:{hashed_pwd}:{salt_b64}\n")
    print(f"User '{username}' added successfully.")

def authenticate_user(username, password):
    if not os.path.exists(USER_FILE):
        return False
    with open(USER_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 3 and parts[0] == username:
                stored_hash = parts[1]
                salt_b64 = parts[2]
                return verify_password(password, stored_hash, salt_b64)
    return False

# --- Server ---
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        with conn:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                return

            parts = data.strip().split(' ', 2)
            username = parts[1] if len(parts) > 1 else 'N/A'
            print(f"Server received: LOGIN {username} ***** from {addr}")

            if len(parts) == 3 and parts[0] == 'LOGIN':
                if authenticate_user(parts[1], parts[2]):
                    conn.sendall(b"LOGIN_SUCCESS")
                    print(f"Authentication successful for {username}")
                else:
                    conn.sendall(b"LOGIN_FAIL")
                    print(f"Authentication failed for {username}")
            else:
                conn.sendall(b"INVALID_REQUEST")
    except ConnectionResetError:
        print(f"[CONNECTION] {addr} disconnected unexpectedly.")
    except Exception as e:
        print(f"[ERROR] {e}")


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[LISTENING] Server is listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()

# --- Client ---
def run_client(username, password):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            request = f"LOGIN {username} {password}"
            s.sendall(request.encode('utf-8'))
            print(f"Client sent login request for user: {username}")

            response = s.recv(1024).decode('utf-8')
            print(f"Server response: {response}")
    except ConnectionRefusedError:
        print(f"Connection refused. Is the server running on {HOST}:{PORT}?")
    except Exception as e:
        print(f"An error occurred: {e}")

# --- Main Execution ---
def print_usage():
    print("Usage: python your_script_name.py <mode> [options]")
    print("Modes:")
    print("  server                    - Start the chat server.")
    print("  adduser <user> <pass>     - Add a new user to the user file.")
    print("  client                    - Run predefined client test cases.")

def run_client_tests():
    print("\n--- Running Client Test Cases ---")
    print("Instructions:")
    print("1. Start the server in a separate terminal: python your_script_name.py server")
    print("2. Add a test user: python your_script_name.py adduser testuser testpass123")
    print("3. The test cases below will now run against the server.\n")

    print("--- Test Case 1: Successful Login ---")
    run_client("testuser", "testpass123")
    
    print("\n--- Test Case 2: Incorrect Password ---")
    run_client("testuser", "wrongpassword")

    print("\n--- Test Case 3: Non-existent User ---")
    run_client("nouser", "anypassword")

    print("\n--- Test Case 4: Another Successful Login ---")
    run_client("testuser", "testpass123")
    
    print("\n--- Test Case 5: Empty Password ---")
    run_client("testuser", "")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "server":
        run_server()
    elif mode == "adduser":
        if len(sys.argv) != 4:
            print("Usage: python your_script_name.py adduser <username> <password>")
        else:
            add_user(sys.argv[2], sys.argv[3])
    elif mode == "client":
        run_client_tests()
    else:
        print_usage()