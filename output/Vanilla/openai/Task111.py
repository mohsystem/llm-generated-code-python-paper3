import threading
import time
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy

class Task111:
    # XML-RPC methods
    @staticmethod
    def add(a, b): return a + b
    @staticmethod
    def subtract(a, b): return a - b
    @staticmethod
    def multiply(a, b): return a * b
    @staticmethod
    def concat(a, b): return str(a) + str(b)
    @staticmethod
    def ping(): return "pong"

def start_server(host="127.0.0.1", port=9091):
    server = SimpleXMLRPCServer((host, port), logRequests=False, allow_none=True)
    server.register_function(Task111.add, "add")
    server.register_function(Task111.subtract, "subtract")
    server.register_function(Task111.multiply, "multiply")
    server.register_function(Task111.concat, "concat")
    server.register_function(Task111.ping, "ping")

    def run():
        server.serve_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return server, t

def client_call(url, method, *params):
    proxy = ServerProxy(url, allow_none=True)
    return getattr(proxy, method)(*params)

if __name__ == "__main__":
    server, thread = start_server()
    time.sleep(0.2)

    url = "http://127.0.0.1:9091"

    # 5 test cases
    r1 = client_call(url, "add", 7, 5)
    r2 = client_call(url, "subtract", 10, 3)
    r3 = client_call(url, "multiply", 6, 7)
    r4 = client_call(url, "concat", "Hello, ", "World")
    r5 = client_call(url, "ping")

    print("add(7,5) =", r1)
    print("subtract(10,3) =", r2)
    print("multiply(6,7) =", r3)
    print("concat('Hello, ', 'World') =", r4)
    print("ping() =", r5)

    server.shutdown()