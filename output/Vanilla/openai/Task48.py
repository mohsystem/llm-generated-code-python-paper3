import threading
from queue import Queue

class Task48:
    class ChatServer:
        def __init__(self):
            self._clients = {}  # name -> Queue
            self._lock = threading.Lock()

        def register_client(self, name: str, inbox: Queue) -> bool:
            if not name or inbox is None:
                return False
            with self._lock:
                if name in self._clients:
                    return False
                self._clients[name] = inbox
                return True

        def unregister_client(self, name: str) -> bool:
            with self._lock:
                return self._clients.pop(name, None) is not None

        def broadcast(self, sender: str, message: str) -> None:
            full = f"{sender}: {message}"
            with self._lock:
                for q in self._clients.values():
                    q.put(full)

        def get_connected_clients(self):
            with self._lock:
                return list(self._clients.keys())

    class ChatClient:
        def __init__(self, name: str, server: 'Task48.ChatServer'):
            self.name = name
            self.server = server
            self.inbox = Queue()

        def connect(self) -> bool:
            return self.server.register_client(self.name, self.inbox)

        def disconnect(self) -> bool:
            return self.server.unregister_client(self.name)

        def send(self, message: str) -> None:
            self.server.broadcast(self.name, message)

        def receive_all(self):
            out = []
            while not self.inbox.empty():
                out.append(self.inbox.get_nowait())
            return out

def _test1():
    print("Test1: Single client")
    srv = Task48.ChatServer()
    a = Task48.ChatClient("Alice", srv)
    a.connect()
    a.send("Hello")
    print("Alice inbox:", a.receive_all())

def _test2():
    print("Test2: Two clients exchange")
    srv = Task48.ChatServer()
    a = Task48.ChatClient("Alice", srv)
    b = Task48.ChatClient("Bob", srv)
    a.connect(); b.connect()
    a.send("Hi Bob"); b.send("Hi Alice")
    print("Alice inbox:", a.receive_all())
    print("Bob inbox:", b.receive_all())

def _test3():
    print("Test3: Three clients multi-broadcast")
    srv = Task48.ChatServer()
    a = Task48.ChatClient("A", srv)
    b = Task48.ChatClient("B", srv)
    c = Task48.ChatClient("C", srv)
    a.connect(); b.connect(); c.connect()
    a.send("One"); b.send("Two"); c.send("Three")
    print("A inbox:", a.receive_all())
    print("B inbox:", b.receive_all())
    print("C inbox:", c.receive_all())

def _test4():
    print("Test4: Disconnect behavior")
    srv = Task48.ChatServer()
    a = Task48.ChatClient("A", srv)
    b = Task48.ChatClient("B", srv)
    a.connect(); b.connect()
    a.send("Before leave")
    b.disconnect()
    a.send("After leave")
    print("A inbox:", a.receive_all())
    print("B inbox (only first expected):", b.receive_all())

def _test5():
    print("Test5: Five clients")
    srv = Task48.ChatServer()
    cs = [Task48.ChatClient(f"C{i}", srv) for i in range(5)]
    for c in cs: c.connect()
    for i, c in enumerate(cs):
        c.send(f"Msg{i}")
    for c in cs:
        print(c.name, "inbox:", c.receive_all())

if __name__ == "__main__":
    _test1()
    _test2()
    _test3()
    _test4()
    _test5()