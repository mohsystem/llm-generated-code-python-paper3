import socket
import threading
import sys
import time
import os

HOST = '127.0.0.1'
PORT = 12346
USER_FILE = "users_py.txt"

# --- SERVER COMPONENT ---

class ClientThread(threading.Thread):
    def __init__(self, client_socket, server_instance):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.server = server_instance

    def run(self):
        try:
            while True:
                data = self.client_socket.recv(1024).decode('utf-8').strip()
                if not data:
                    break
                print(f"Server received: {data}")
                parts = data.split(' ')
                command = parts[0]

                if command.upper() == "LOGIN" and len(parts) == 3:
                    response = self.server.authenticate(parts[1], parts[2])
                    self.client_socket.send(response.encode('utf-8'))
                elif command.upper() == "SHUTDOWN":
                    print("Server received shutdown command.")
                    self.server.stop()
                    break
                else:
                    self.client_socket.send("ERROR Unknown command".encode('utf-8'))
        except ConnectionResetError:
            print("Client disconnected abruptly.")
        finally:
            self.client_socket.close()

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.users = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False

    def load_users(self):
        try:
            with open(USER_FILE, 'r') as f:
                for line in f:
                    parts = line.strip().split(':', 1)
                    if len(parts) == 2:
                        self.users[parts[0]] = parts[1]
            print(f"Users loaded from {USER_FILE}")
        except FileNotFoundError:
            print(f"User file {USER_FILE} not found.")

    def authenticate(self, username, password):
        if username not in self.users:
            return "LOGIN_FAIL User not found"
        if self.users[username] == password:
            return "LOGIN_SUCCESS"
        else:
            return "LOGIN_FAIL Invalid password"

    def start(self):
        self.load_users()
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        print(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                client_sock, _ = self.server_socket.accept()
                new_thread = ClientThread(client_sock, self)
                new_thread.start()
            except OSError: # Socket closed
                break
        print("Server has stopped.")

    def stop(self):
        self.running = False
        # To unblock accept() call
        try:
            # This connection will immediately be closed, but it wakes up the accept() call.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
        except ConnectionRefusedError:
             pass # Server might already be closing
        finally:
            self.server_socket.close()

# --- CLIENT COMPONENT ---

def run_client():
    print("\n--- Starting Client Test Cases ---")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            def send_and_receive(request):
                print(f"Client sent: {request}")
                s.sendall(request.encode('utf-8'))
                response = s.recv(1024).decode('utf-8')
                print(f"Server response: {response}")

            # Test Case 1: Successful login
            print("Client> Test 1: Correct credentials (alice)")
            send_and_receive("LOGIN alice pass123\n")

            # Test Case 2: Incorrect password
            print("\nClient> Test 2: Incorrect password (bob)")
            send_and_receive("LOGIN bob wrongpass\n")
            
            # Test Case 3: User not found
            print("\nClient> Test 3: User not found (dave)")
            send_and_receive("LOGIN dave somepass\n")

            # Test Case 4: Another successful login
            print("\nClient> Test 4: Correct credentials (charlie)")
            send_and_receive("LOGIN charlie qwerty\n")

            # Test Case 5: Malformed request
            print("\nClient> Test 5: Malformed request")
            send_and_receive("LOGI charlie qwerty\n")
            
            # Send shutdown signal
            s.sendall("SHUTDOWN\n".encode('utf-8'))

    except Exception as e:
        print(f"Client error: {e}")
    finally:
        print("--- Client Test Cases Finished ---")


# --- MAIN EXECUTION ---

def main():
    # 1. Create user file
    with open(USER_FILE, 'w') as f:
        f.write("alice:pass123\n")
        f.write("bob:secret\n")
        f.write("charlie:qwerty\n")

    # 2. Start server in a background thread
    server = Server(HOST, PORT)
    server_thread = threading.Thread(target=server.start)
    server_thread.start()

    # 3. Wait for the server to be ready
    time.sleep(1) 

    # 4. Run client test cases
    run_client()

    # 5. Wait for server to shut down
    server_thread.join()

    # 6. Clean up
    os.remove(USER_FILE)
    print("\nProgram finished.")

if __name__ == "__main__":
    main()