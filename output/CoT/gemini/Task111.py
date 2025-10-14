import threading
import time
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import xmlrpc.client

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

# A simple calculator class to be exposed
class Calculator:
    def add(self, x, y):
        """Adds two integers."""
        return x + y

    def subtract(self, x, y):
        """Subtracts two integers."""
        return x - y

def run_server(host="localhost", port=8080):
    """Function to run the XML-RPC server."""
    with SimpleXMLRPCServer((host, port),
                            requestHandler=RequestHandler,
                            logRequests=False, # Set to True for debugging
                            allow_none=True) as server:
        server.register_introspection_functions()

        # Register an instance of the Calculator class
        server.register_instance(Calculator(), allow_dotted_names=True)
        print(f"XML-RPC server listening on {host}:{port}...")
        
        # Store the server instance so the main thread can shut it down
        global server_instance
        server_instance = server
        
        server.serve_forever()

def run_test_client(host="localhost", port=8080):
    """Function to run client test cases."""
    # Wait for the server to be ready
    time.sleep(1) 
    
    try:
        proxy = xmlrpc.client.ServerProxy(f"http://{host}:{port}/RPC2")

        print("\n--- Running Client Test Cases ---")

        # Test Case 1
        result1 = proxy.add(5, 3)
        print(f"Test 1: add(5, 3) = {result1}")

        # Test Case 2
        result2 = proxy.add(-10, 5)
        print(f"Test 2: add(-10, 5) = {result2}")

        # Test Case 3
        result3 = proxy.add(0, 0)
        print(f"Test 3: add(0, 0) = {result3}")
        
        # Test Case 4
        result4 = proxy.add(12345, 67890)
        print(f"Test 4: add(12345, 67890) = {result4}")

        # Test Case 5
        result5 = proxy.subtract(10, 4)
        print(f"Test 5: subtract(10, 4) = {result5}")

    except Exception as e:
        print(f"Client test failed: {e}")


if __name__ == "__main__":
    HOST, PORT = "localhost", 8080
    server_instance = None
    
    # Run the server in a separate thread
    server_thread = threading.Thread(target=run_server, args=(HOST, PORT))
    server_thread.daemon = True
    server_thread.start()

    # Run client tests
    run_test_client(HOST, PORT)

    # Shutdown the server
    if server_instance:
        print("\nShutting down the server.")
        server_instance.shutdown()
        server_instance.server_close()