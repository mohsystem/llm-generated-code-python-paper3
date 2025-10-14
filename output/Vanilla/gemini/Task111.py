# This code uses Python's standard library `xmlrpc.server`.
# No external libraries are needed.
#
# To run:
# python your_script_name.py
#
# A client can then connect to http://localhost:8081 and call the functions.
# Example client call:
# import xmlrpc.client
# with xmlrpc.client.ServerProxy("http://localhost:8081/") as proxy:
#     print(proxy.add(5, 3))

from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

def main():
    port = 8081
    # Create server
    with SimpleXMLRPCServer(('localhost', port),
                            requestHandler=RequestHandler,
                            allow_none=True) as server:
        server.register_introspection_functions()

        print(f"Starting XML-RPC server on port {port}...")
        print("Available methods: add, subtract, greet, get_dict, get_list")

        # Test Case 1: Add two integers
        def add(x, y):
            print(f"Called add({x}, {y})")
            return x + y
        server.register_function(add, 'add')

        # Test Case 2: Subtract two floats
        def subtract(x, y):
            print(f"Called subtract({x}, {y})")
            return x - y
        server.register_function(subtract, 'subtract')
        
        # Test Case 3: Greet a user by name
        def greet(name):
            print(f"Called greet('{name}')")
            return f"Hello, {name}!"
        server.register_function(greet, 'greet')
        
        # Test Case 4: Return a dictionary (struct)
        def get_dict(name, age):
            print(f"Called get_dict('{name}', {age})")
            return {'name': name, 'age': age, 'isAdult': age >= 18}
        server.register_function(get_dict, 'get_dict')

        # Test Case 5: Return a list (array)
        def get_list():
            print("Called get_list()")
            return ["Java", "Python", "CPP", "C"]
        server.register_function(get_list, 'get_list')

        # Run the server's main loop
        server.serve_forever()

if __name__ == "__main__":
    main()