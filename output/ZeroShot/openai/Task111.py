import threading
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from xmlrpc.client import ServerProxy
import socket
import time

class SecureRequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

def sum_list(arr):
    if not isinstance(arr, list):
        raise ValueError("Expected list")
    total = 0
    for v in arr:
        if not isinstance(v, (int, bool)):  # bool is subclass of int; still allowed
            raise ValueError("Non-integer in list")
        total += int(v)
        if total > 2**31-1 or total < -2**31:
            raise ValueError("Sum overflow")
    return int(total)

def multiply(a, b):
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("Expected integers")
    prod = a * b
    if prod > 2**31-1 or prod < -2**31:
        raise ValueError("Multiply overflow")
    return int(prod)

def concat(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        raise ValueError("Expected strings")
    if len(a) + len(b) > 1_000_000:
        raise ValueError("String too long")
    return a + b

def ping():
    return "pong"

def echo(s):
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    if len(s) > 1_000_000:
        raise ValueError("String too long")
    return s

def run_server(host='127.0.0.1', port=18081, ready_evt=None, stop_evt=None):
    with SimpleXMLRPCServer((host, port), requestHandler=SecureRequestHandler, allow_none=False, logRequests=False) as server:
        server.register_introspection_functions()
        server.register_function(sum_list, 'sum')
        server.register_function(multiply, 'multiply')
        server.register_function(concat, 'concat')
        server.register_function(ping, 'ping')
        server.register_function(echo, 'echo')
        if ready_evt:
            ready_evt.set()
        while not (stop_evt and stop_evt.is_set()):
            server.handle_request()

if __name__ == '__main__':
    ready = threading.Event()
    stop = threading.Event()
    t = threading.Thread(target=run_server, kwargs={'ready_evt': ready, 'stop_evt': stop}, daemon=True)
    t.start()
    ready.wait(timeout=2.0)
    time.sleep(0.1)

    client = ServerProxy('http://127.0.0.1:18081/RPC2', allow_none=False)
    r1 = client.sum([1,2,3,4,5])
    r2 = client.multiply(6, 7)
    r3 = client.concat("Hello, ", "World!")
    r4 = client.ping()
    r5 = client.echo("SampleText")

    print(r1)
    print(r2)
    print(r3)
    print(r4)
    print(r5)

    stop.set()
    t.join(timeout=1.0)