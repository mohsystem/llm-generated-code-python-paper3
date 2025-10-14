from __future__ import annotations
import threading
from queue import Queue, Empty
from typing import List, Dict

class ChatMessage:
    def __init__(self, sender: str, text: str) -> None:
        self.sender = sender
        self.text = text

    def format(self) -> str:
        return f"{self.sender}: {self.text}"

class ChatClient:
    def __init__(self, name: str) -> None:
        self._name = name
        self._id = -1
        self._inbox: Queue[str] = Queue()

    @property
    def name(self) -> str:
        return self._name

    @property
    def id(self) -> int:
        return self._id

    def set_id(self, cid: int) -> bool:
        if cid <= 0:
            return False
        self._id = cid
        return True

    def receive(self, from_name: str, message: str) -> bool:
        if not ChatServer.validate_message(message) or not ChatServer.validate_name(from_name):
            return False
        try:
            self._inbox.put_nowait(f"{from_name}: {message}")
            return True
        except Exception:
            return False

    def fetch_messages(self, max_count: int) -> List[str]:
        if max_count <= 0:
            return []
        msgs: List[str] = []
        for _ in range(max_count):
            try:
                msgs.append(self._inbox.get_nowait())
            except Empty:
                break
        return msgs

    def send(self, server: "ChatServer", message: str) -> int:
        return server.broadcast(self._id, self._name, message)

class ChatServer:
    MAX_CLIENTS = 1000
    MAX_NAME_LEN = 32
    MAX_MSG_LEN = 256

    def __init__(self) -> None:
        self._clients: Dict[int, ChatClient] = {}
        self._lock = threading.RLock()
        self._next_id = 1

    def connect(self, client: ChatClient) -> int:
        if client is None or not self.validate_name(client.name):
            return -1
        with self._lock:
            if len(self._clients) >= self.MAX_CLIENTS:
                return -1
            cid = self._next_id
            self._next_id += 1
            client.set_id(cid)
            self._clients[cid] = client
            return cid

    def disconnect(self, cid: int) -> bool:
        with self._lock:
            return self._clients.pop(cid, None) is not None

    def broadcast(self, sender_id: int, sender_name: str, message: str) -> int:
        if not self.validate_name(sender_name) or not self.validate_message(message):
            return 0
        with self._lock:
            if sender_id not in self._clients:
                return 0
            delivered = 0
            for cid, c in list(self._clients.items()):
                if cid == sender_id:
                    continue
                if c.receive(sender_name, message):
                    delivered += 1
            return delivered

    def get_connected_names(self) -> List[str]:
        with self._lock:
            return [c.name for c in self._clients.values()]

    @staticmethod
    def validate_name(name: str) -> bool:
        if not isinstance(name, str):
            return False
        ln = len(name.encode("utf-8"))
        return 0 < ln <= ChatServer.MAX_NAME_LEN

    @staticmethod
    def validate_message(msg: str) -> bool:
        if not isinstance(msg, str):
            return False
        lm = len(msg.encode("utf-8"))
        return 0 < lm <= ChatServer.MAX_MSG_LEN

def assert_true(cond: bool, name: str) -> None:
    print(("PASS: " if cond else "FAIL: ") + name)

def main() -> None:
    # Test 1
    server = ChatServer()
    a = ChatClient("Alice")
    b = ChatClient("Bob")
    aid = server.connect(a)
    bid = server.connect(b)
    assert_true(aid > 0 and bid > 0, "Test1: connect clients")
    d1 = a.send(server, "Hello Bob")
    a_inbox1 = a.fetch_messages(100)
    b_inbox1 = b.fetch_messages(100)
    assert_true(d1 == 1, "Test1: delivered count == 1")
    assert_true(len(a_inbox1) == 0, "Test1: A did not receive own message")
    assert_true(len(b_inbox1) == 1 and b_inbox1[0] == "Alice: Hello Bob", "Test1: B received message")

    # Test 2
    c = ChatClient("Carol")
    cid = server.connect(c)
    assert_true(cid > 0, "Test2: connect C")
    d2 = c.send(server, "Hi all")
    a_inbox2 = a.fetch_messages(100)
    b_inbox2 = b.fetch_messages(100)
    c_inbox2 = c.fetch_messages(100)
    assert_true(d2 == 2, "Test2: delivered to A and B")
    assert_true(a_inbox2 == ["Carol: Hi all"], "Test2: A received from C")
    assert_true(b_inbox2 == ["Carol: Hi all"], "Test2: B received from C")
    assert_true(len(c_inbox2) == 0, "Test2: C did not receive own message")

    # Test 3
    disc = server.disconnect(bid)
    assert_true(disc, "Test3: disconnect B")
    d3 = a.send(server, "After B left")
    c_inbox3 = c.fetch_messages(100)
    b_inbox3 = b.fetch_messages(100)
    assert_true(d3 == 1, "Test3: delivered only to C")
    assert_true(c_inbox3 == ["Alice: After B left"], "Test3: C got message")
    assert_true(len(b_inbox3) == 0, "Test3: B got nothing after disconnect")

    # Test 4
    d4a = a.send(server, "")
    d4b = a.send(server, "x" * 300)
    assert_true(d4a == 0 and d4b == 0, "Test4: invalid messages not delivered")

    # Test 5 concurrency
    d = ChatClient("Dave")
    e = ChatClient("Eve")
    f = ChatClient("Frank")
    server.connect(d)
    server.connect(e)
    server.connect(f)

    def sender(client: ChatClient, prefix: str) -> None:
        for i in range(10):
            client.send(server, f"{prefix}{i}")

    t1 = threading.Thread(target=sender, args=(d, "d"))
    t2 = threading.Thread(target=sender, args=(e, "e"))
    t3 = threading.Thread(target=sender, args=(f, "f"))
    t1.start(); t2.start(); t3.start()
    t1.join(); t2.join(); t3.join()

    d_in = d.fetch_messages(1000)
    e_in = e.fetch_messages(1000)
    f_in = f.fetch_messages(1000)
    assert_true(len(d_in) == 20 and len(e_in) == 20 and len(f_in) == 20, "Test5: each got 20 messages")

    print("Connected clients:", server.get_connected_names())

if __name__ == "__main__":
    main()