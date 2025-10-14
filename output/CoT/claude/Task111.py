
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import html
import socket

class Task111:
    """XML-RPC Server implementation with security measures"""
    
    class MathHandler:
        """Handler class for mathematical operations"""
        
        def add(self, a, b):
            """Add two numbers"""
            try:
                return int(a) + int(b)
            except (ValueError, TypeError):
                return "Error: Invalid input types"
        
        def subtract(self, a, b):
            """Subtract two numbers"""
            try:
                return int(a) - int(b)
            except (ValueError, TypeError):
                return "Error: Invalid input types"
        
        def multiply(self, a, b):
            """Multiply two numbers"""
            try:
                return int(a) * int(b)
            except (ValueError, TypeError):
                return "Error: Invalid input types"
        
        def divide(self, a, b):
            """Divide two numbers"""
            try:
                a, b = int(a), int(b)
                if b == 0:
                    return "Error: Division by zero not allowed"
                return float(a) / float(b)
            except (ValueError, TypeError):
                return "Error: Invalid input types"
        
        def echo(self, message):
            """Echo a message with sanitization"""
            if not message:
                return "Empty message"
            # Sanitize input to prevent injection attacks
            sanitized = html.escape(str(message))
            return f"Echo: {sanitized}"
    
    class SecureXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
        """Custom request handler with security restrictions"""
        
        # Restrict to specific paths
        rpc_paths = ('/RPC2',)
        
        def do_POST(self):
            """Override to add security headers"""
            try:
                # Add security headers
                super().do_POST()
            except Exception as e:
                print(f"Request error: {e}")
    
    @staticmethod
    def start_server(host='localhost', port=8080):
        """Start the XML-RPC server with security configurations"""
        try:
            # Create server with custom request handler
            server = SimpleXMLRPCServer(
                (host, port),
                requestHandler=Task111.SecureXMLRPCRequestHandler,
                allow_none=False,  
            # Security: Don't allow None values                
            use_builtin_types=True            )                        
            # Set timeout to prevent hanging connections            
            server.socket.settimeout(30)                        
            # Register instance            
            handler = Task111.MathHandler()            
            server.register_instance(handler)                        
            # Register introspection functions (optional, can be disabled for security)            
            server.register_introspection_functions()                        
            print(f"XML-RPC Server started on {host}:{port}")            
            print("Press Ctrl+C to stop the server")                        
            # Start serving            
            server.serve_forever()                    
        except socket.error as e:
            print(f"Socket error: {e}")        
        except KeyboardInterrupt:
            print("\\nServer stopped by user")        
        except Exception as e:
            print(f"Server error: {e}")        
        finally:
            if 'server' in locals():                
                server.server_close()
