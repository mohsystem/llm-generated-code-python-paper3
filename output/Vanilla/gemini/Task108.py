import sys
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy, Fault

# The object that will be exposed remotely
class Calculator:
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b

    def multiply(self, a, b):
        return a * b

    def divide(self, a, b):
        if b == 0:
            # XML-RPC raises a Fault for exceptions
            raise ValueError("Error: Division by zero.")
        return a / b

def run_server(host="localhost", port=8000):
    """Starts the XML-RPC server."""
    with SimpleXMLRPCServer((host, port)) as server:
        server.register_instance(Calculator())
        print(f"Serving XML-RPC on {host}:{port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServer shutting down.")

def run_client(host="localhost", port=8000):
    """Runs the client with test cases."""
    try:
        proxy = ServerProxy(f"http://{host}:{port}/")
        print(f"Client connected to server at {host}:{port}")
        print("--- Running Test Cases ---")
        
        # Test Case 1: Addition
        a, b = 5, 3
        result = proxy.add(a, b)
        print(f"Test 1: {a} + {b} = {result}")
        
        # Test Case 2: Subtraction
        a, b = 10, 4
        result = proxy.subtract(a, b)
        print(f"Test 2: {a} - {b} = {result}")

        # Test Case 3: Multiplication
        a, b = 7, 6
        result = proxy.multiply(a, b)
        print(f"Test 3: {a} * {b} = {result}")

        # Test Case 4: Division
        a, b = 20, 5
        result = proxy.divide(a, b)
        print(f"Test 4: {a} / {b} = {result}")

        # Test Case 5: Division by zero
        try:
            a, b = 10, 0
            print(f"Test 5: {a} / {b} -> ", end="")
            proxy.divide(a, b)
        except Fault as f:
            print(f"Successfully caught expected exception: {f.faultString}")

    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is the server running on {host}:{port}?")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def main():
    """
    Main function to launch server or client.
    --- How to Run ---
    1. Start Server in one terminal: python your_script_name.py server
    2. Start Client in another terminal: python your_script_name.py client
    """
    if len(sys.argv) < 2 or sys.argv[1] not in ["server", "client"]:
        print("Usage: python Task108.py <server|client>")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()

if __name__ == "__main__":
    # In a real application, you might use a class name matching the file.
    # For this task, the class name 'Task108' is not used directly in Python.
    main()