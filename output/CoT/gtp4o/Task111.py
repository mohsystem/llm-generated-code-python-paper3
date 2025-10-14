# Chain-of-Through Steps are embedded as comments:
# 1) Problem understanding: Implement a secure XML-RPC server and client tests.
# 2) Security: enforce request size limits, content-type validation, local bind, no code injection.
# 3-5) Secure generation, review, final secure output.

import threading
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import xmlrpc.client
import socket

# Server methods (accept inputs and return outputs)
def add(a, b):
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("Expected integers")
    return a + b

def multiply(a, b):
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("Expected integers")
    return a * b

def concat(a, b):
    a = "" if a is None else str(a).replace("\r", "").replace("\n", "")
    b = "" if b is None else str(b).replace("\r", "").replace("\n", "")
    return a + b

def echo(s):
    s = "" if s is None else str(s)
    return s.replace("\r", "").replace("\n", "")

def ping():
    return "pong"

class SecureXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)
    max_request_size = 100 * 1024

    def do_POST(self):
        ct = self.headers.get('content-type', '')
        if 'text/xml' not in ct.lower():
            self.send_error(415, "Unsupported Media Type")
            return
        try:
            cl = int(self.headers.get('content-length', '0'))
        except Exception:
            cl = 0
        if cl <= 0 or cl > self.max_request_size:
            self.send_error(413, "Request Entity Too Large")
            return
        return super().do_POST()

def start_server(server):
    server.serve_forever()

def xmlrpc_call(url, method, params):
    with xmlrpc.client.ServerProxy(url, allow_none=False) as proxy:
        func = getattr(proxy, method)
        if params is None:
            params = []
        return func(*params)

if __name__ == "__main__":
    # Bind to localhost on ephemeral port
    with SimpleXMLRPCServer(("127.0.0.1", 0), requestHandler=SecureXMLRPCRequestHandler, logRequests=False, allow_none=False) as server:
        server.register_function(add, 'add')
        server.register_function(multiply, 'multiply')
        server.register_function(concat, 'concat')
        server.register_function(echo, 'echo')
        server.register_function(ping, 'ping')

        host, port = server.server_address
        t = threading.Thread(target=start_server, args=(server,), daemon=True)
        t.start()

        url = f"http://127.0.0.1:{port}/RPC2"

        # 5 test cases
        print("Test1 add:", xmlrpc_call(url, "add", [7, 5]))
        print("Test2 multiply:", xmlrpc_call(url, "multiply", [6, 9]))
        print("Test3 concat:", xmlrpc_call(url, "concat", ["Hello, ", "XML-RPC"]))
        print("Test4 echo:", xmlrpc_call(url, "echo", ["safe <message> & chars"]))
        print("Test5 ping:", xmlrpc_call(url, "ping", []))

        server.shutdown()
        server.server_close()