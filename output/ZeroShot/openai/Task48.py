import threading
from typing import Dict, List

class Client:
    def __init__(self, cid: int, name: str):
        self.id = cid
        self.name = name
        self._inbox: List[str] = []
        self._lock = threading.Lock()

    def receive(self, msg: str) -> None:
        if msg is None:
            return
        with self._lock:
            # Bound inbox size to avoid unbounded memory growth
            if len(self._inbox) > 10000:
                self._inbox.clear()
            self._inbox.append(msg)

    def fetch_all(self) -> List[str]:
        with self._lock:
            msgs = list(self._inbox)
            self._inbox.clear()
            return msgs

class ChatServer:
    def __init__(self):
        self._next_id = 1
        self._clients: Dict[int, Client] = {}
        self._lock = threading.Lock()

    def register_client(self, name: str) -> int:
        safe_name = self._sanitize_name(name)
        if not safe_name:
            safe_name = f"user{self._next_id}"
        with self._lock:
            cid = self._next_id
            self._next_id += 1
            self._clients[cid] = Client(cid, safe_name)
            return cid

    def disconnect_client(self, client_id: int) -> bool:
        with self._lock:
            return self._clients.pop(client_id, None) is not None

    def get_client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def get_client_messages(self, client_id: int) -> List[str]:
        with self._lock:
            c = self._clients.get(client_id)
        if c is None:
            return []
        return c.fetch_all()

    def send_from(self, client_id: int, message: str) -> int:
        with self._lock:
            sender = self._clients.get(client_id)
            if sender is None:
                return 0
            sanitized = self._sanitize_message(message)
            if not sanitized:
                return 0
            payload = f"{sender.name}: {sanitized}"
            # Snapshot of clients to broadcast outside lock to reduce contention
            recipients = list(self._clients.values())
        count = 0
        for c in recipients:
            c.receive(payload)
            count += 1
        return count

    @staticmethod
    def _sanitize_message(msg: str) -> str:
        if msg is None:
            return ""
        out = []
        max_len = 256
        for ch in msg:
            if len(out) >= max_len:
                break
            code = ord(ch)
            if 32 <= code < 127:
                out.append(ch)
            elif ch in ('\n', '\r', '\t'):
                out.append(' ')
        return ''.join(out).strip()

    @staticmethod
    def _sanitize_name(name: str) -> str:
        if name is None:
            return ""
        out = []
        for ch in name:
            if len(out) >= 32:
                break
            code = ord(ch)
            if 33 <= code < 127 and ch != ':':
                out.append(ch)
        return ''.join(out).strip()

def _print_inbox(label: str, msgs: List[str]) -> None:
    print(f"{label} ({len(msgs)}):")
    for m in msgs:
        print(f"  {m}")

def main():
    server = ChatServer()

    alice = server.register_client("Alice")
    bob = server.register_client("Bob")
    charlie = server.register_client("Charlie")

    print("Test 1: Single client receives own message")
    server.send_from(alice, "Hello everyone!")
    _print_inbox("Alice inbox after send", server.get_client_messages(alice))
    _print_inbox("Bob inbox", server.get_client_messages(bob))
    _print_inbox("Charlie inbox", server.get_client_messages(charlie))
    print("----")

    print("Test 2: Control chars sanitized")
    server.send_from(bob, "Hi\nthere\tall!")
    _print_inbox("Alice inbox", server.get_client_messages(alice))
    _print_inbox("Bob inbox", server.get_client_messages(bob))
    _print_inbox("Charlie inbox", server.get_client_messages(charlie))
    print("----")

    print("Test 3: Long message truncated")
    long_msg = "X" * 400
    server.send_from(charlie, long_msg)
    _print_inbox("Alice inbox", server.get_client_messages(alice))
    print("----")

    print("Test 4: Empty/invalid message rejected")
    count = server.send_from(alice, "\x01\x02\x03")
    print(f"Broadcast count (should be 0): {count}")
    _print_inbox("Bob inbox", server.get_client_messages(bob))
    print("----")

    print("Test 5: Disconnect behavior")
    server.disconnect_client(charlie)
    server.send_from(bob, "After disconnect")
    _print_inbox("Alice inbox", server.get_client_messages(alice))
    _print_inbox("Charlie inbox (should be empty)", server.get_client_messages(charlie))
    print(f"Active clients: {server.get_client_count()}")

if __name__ == "__main__":
    main()