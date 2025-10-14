
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import threading

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class Task111:
    
    class Calculator:
        def add(self, a, b):
            return a + b
        
        def subtract(self, a, b):
            return a - b
        
        def multiply(self, a, b):
            return a * b
        
        def divide(self, a, b):
            if b == 0:
                raise ValueError("Division by zero")
            return float(a) / float(b)
        
        def echo(self, message):
            return f"Echo: {message}"
    
    @staticmethod
    def start_server(host='localhost', port=8080):
        try:
            server = SimpleXMLRPCServer(
                (host, port),
                requestHandler=RequestHandler,
                allow_none=True
            )
            server.register_introspection_functions()
            
            calc = Task111.Calculator()
            server.register_instance(calc, allow_dotted_names=False)
            
            print(f"XML-RPC Server started on {host}:{port}")
            server.serve_forever()
            
        except Exception as e:
            print(f"Error starting server: {e}")
    
    @staticmethod
    def start_server_thread(host='localhost', port=8080):
        server_thread = threading.Thread(
            target=Task111.start_server,
            args=(host, port),
            daemon=True
        )
        server_thread.start()
        return server_thread

if __name__ == "__main__":
    print("Starting XML-RPC Server Demo...")
    
    calc = Task111.Calculator()
    
    print("\\nTest Case 1 - Addition:")
    print(f"5 + 3 = {calc.add(5, 3)}")
    
    print("\\nTest Case 2 - Subtraction:")
    print(f"10 - 4 = {calc.subtract(10, 4)}")
    
    print("\\nTest Case 3 - Multiplication:")
    print(f"6 * 7 = {calc.multiply(6, 7)}")
    
    print("\\nTest Case 4 - Division:")
    print(f"20 / 4 = {calc.divide(20, 4)}")
    
    print("\\nTest Case 5 - Echo:")
    print(calc.echo("Hello World"))
    
    print("\\nServer would start on localhost:8080")
    # Uncomment to actually start the server
    # Task111.start_server('localhost', 8080)
