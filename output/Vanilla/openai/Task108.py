import socket
import threading
import time

PORT = 5050

class RemoteServer(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.running = True
        self.store = {}
        self.server_socket = None

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ss:
            ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ss.bind(("127.0.0.1", self.port))
            ss.listen(5)
            self.server_socket = ss
            while self.running:
                try:
                    client, _ = ss.accept()
                except OSError:
                    break
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

    def handle_client(self, client):
        with client:
            f = client.makefile(mode="rwb")
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.decode().rstrip("\n")
                resp = self.process(line)
                f.write((resp + "\n").encode())
                f.flush()
                if line.strip().upper() in ("EXIT", "SHUTDOWN"):
                    break

    def process(self, line: str) -> str:
        if not line.strip():
            return "ERROR Empty command"
        parts = line.strip().split(" ", 3)
        cmd = parts[0].upper()
        if cmd == "CREATE":
            if len(parts) < 2:
                return "ERROR Usage: CREATE <id>"
            self.store.setdefault(parts[1], {})
            return "OK"
        elif cmd == "SET":
            if len(parts) < 4:
                return "ERROR Usage: SET <id> <key> <value>"
            obj = self.store.get(parts[1])
            if obj is None:
                return "ERROR NotFound"
            obj[parts[2]] = parts[3]
            return "OK"
        elif cmd == "GET":
            if len(parts) < 3:
                return "ERROR Usage: GET <id> <key>"
            obj = self.store.get(parts[1])
            if obj is None or parts[2] not in obj:
                return "ERROR NotFound"
            return "VALUE " + str(obj[parts[2]])
        elif cmd == "DELETE":
            if len(parts) < 2:
                return "ERROR Usage: DELETE <id>"
            self.store.pop(parts[1], None)
            return "OK"
        elif cmd == "KEYS":
            if len(parts) < 2:
                return "ERROR Usage: KEYS <id>"
            obj = self.store.get(parts[1])
            if obj is None:
                return "ERROR NotFound"
            return "KEYS " + ",".join(sorted(obj.keys()))
        elif cmd == "LIST":
            return "LIST " + ",".join(sorted(self.store.keys()))
        elif cmd == "EXIT":
            return "OK BYE"
        elif cmd == "SHUTDOWN":
            self.running = False
            try:
                if self.server_socket:
                    self.server_socket.close()
            except Exception:
                pass
            return "OK SHUTDOWN"
        else:
            return "ERROR UnknownCommand"

# Client helpers - functions take parameters and return output
def send_command(cmd: str) -> str:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=2.0) as s:
            s.sendall((cmd + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            return data.decode().rstrip("\n")
    except Exception as e:
        return "ERROR " + str(e)

def create(obj_id: str) -> str: return send_command(f"CREATE {obj_id}")
def set_prop(obj_id: str, key: str, value: str) -> str: return send_command(f"SET {obj_id} {key} {value}")
def get_prop(obj_id: str, key: str) -> str: return send_command(f"GET {obj_id} {key}")
def delete_obj(obj_id: str) -> str: return send_command(f"DELETE {obj_id}")
def keys(obj_id: str) -> str: return send_command(f"KEYS {obj_id}")
def list_objs() -> str: return send_command("LIST")
def shutdown() -> str: return send_command("SHUTDOWN")

if __name__ == "__main__":
    server = RemoteServer(PORT)
    server.start()
    time.sleep(0.2)

    # Test case 1
    print(create("foo"))
    print(set_prop("foo", "a", "1"))
    print(get_prop("foo", "a"))

    # Test case 2
    print(create("bar"))
    print(set_prop("bar", "x", "hello world"))
    print(keys("bar"))

    # Test case 3
    print(list_objs())

    # Test case 4
    print(delete_obj("foo"))
    print(list_objs())

    # Test case 5
    print(get_prop("foo", "a"))
    print(get_prop("bar", "missing"))

    print(shutdown())