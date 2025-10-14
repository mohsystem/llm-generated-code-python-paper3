# ================================================================================
# Instructions for Python (XML-RPC over HTTPS):
# 1.  This script requires Python 3.
# 2.  Generate a self-signed SSL certificate for the server. In your terminal, run:
#     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
#     This will create key.pem and cert.pem in the current directory.
#
# 3.  Start the server:
#     python your_script_name.py server
#
# 4.  In another terminal, run the client to execute test cases:
#     python your_script_name.py client
# ================================================================================
import sys
import ssl
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy

HOST = 'localhost'
PORT = 8443
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
SECRET_TOKEN = 'secret-python-token-123'

# The "remote object" is this class instance
class RemoteObjectManager:
    def __init__(self):
        self._data = {}

    def _check_token(self, token):
        if token != SECRET_TOKEN:
            raise ValueError("Authentication failed: Invalid token")

    def get(self, token, key):
        self._check_token(token)
        return self._data.get(key)

    def put(self, token, key, value):
        self._check_token(token)
        self._data[key] = value
        return True

    def delete(self, token, key):
        self._check_token(token)
        if key in self._data:
            return self._data.pop(key)
        return None

def start_server():
    """Starts the secure XML-RPC server."""
    try:
        print(f"Starting secure XML-RPC server on https://{HOST}:{PORT}...")
        server = SimpleXMLRPCServer((HOST, PORT), logRequests=True)
        
        # Wrap the server's socket with SSL/TLS
        server.socket = ssl.wrap_socket(
            server.socket,
            server_side=True,
            certfile=CERT_FILE,
            keyfile=KEY_FILE,
            ssl_version=ssl.PROTOCOL_TLS
        )
        
        server.register_instance(RemoteObjectManager())
        print("Server is ready and listening.")
        server.serve_forever()
    except FileNotFoundError:
        print(f"Error: Certificate files '{CERT_FILE}' or '{KEY_FILE}' not found.")
        print("Please generate them using the openssl command in the instructions.")
    except Exception as e:
        print(f"Server error: {e}")

def run_client_tests():
    """Runs client test cases against the server."""
    try:
        print("Running client tests...")
        
        # Create an SSL context that trusts our self-signed certificate
        # For a real application, you would use a proper CA
        context = ssl.create_default_context(cafile=CERT_FILE)
        
        # Connect to the secure server
        server_url = f"https://{HOST}:{PORT}"
        proxy = ServerProxy(server_url, context=context)
        print(f"Connected to {server_url}")

        # Test Case 1: Put a new key-value pair
        print("\n--- Test Case 1: Put new item ---")
        result = proxy.put(SECRET_TOKEN, "user1", "data123")
        print(f"put('user1', 'data123') -> {result}")
        assert result

        # Test Case 2: Get the value for the new key
        print("\n--- Test Case 2: Get new item ---")
        value = proxy.get(SECRET_TOKEN, "user1")
        print(f"get('user1') -> {value}")
        assert value == "data123"

        # Test Case 3: Update the value for an existing key
        print("\n--- Test Case 3: Update existing item ---")
        result = proxy.put(SECRET_TOKEN, "user1", "data456")
        print(f"put('user1', 'data456') -> {result}")
        assert result

        # Test Case 4: Get the updated value
        print("\n--- Test Case 4: Get updated item ---")
        value = proxy.get(SECRET_TOKEN, "user1")
        print(f"get('user1') -> {value}")
        assert value == "data456"

        # Test Case 5: Delete the key
        print("\n--- Test Case 5: Delete item ---")
        deleted_value = proxy.delete(SECRET_TOKEN, "user1")
        print(f"delete('user1') -> {deleted_value}")
        assert deleted_value == "data456"
        value = proxy.get(SECRET_TOKEN, "user1")
        print(f"get('user1') after delete -> {value}")
        assert value is None

        # Test Case 6: Authentication Failure
        print("\n--- Test Case 6: Authentication Failure ---")
        try:
            proxy.get("wrong-token", "user1")
        except Exception as e:
            print(f"Caught expected exception: {e}")

        print("\nAll client tests completed.")

    except FileNotFoundError:
        print(f"Error: Certificate file '{CERT_FILE}' not found.")
        print("Please ensure the client can access the server's cert file.")
    except ConnectionRefusedError:
        print("Error: Connection refused. Is the server running?")
    except Exception as e:
        print(f"Client error: {e}")


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage: python", sys.argv[0], " <server|client>")
        sys.exit(1)
    
    mode = sys.argv[1]
    if mode == 'server':
        start_server()
    elif mode == 'client':
        run_client_tests()