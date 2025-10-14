import socket
import struct
import threading
import time

# Step 1-5 integrated via secure programming practices and comments.

def build_dns_query(name: str, qtype: int, qid: int) -> bytes:
    if not name or qtype <= 0 or qtype > 65535:
        raise ValueError("Invalid params")
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in name.split("."):
        lb = label.encode("ascii")
        if len(lb) == 0 or len(lb) > 63:
            raise ValueError("Invalid label length")
        qname += struct.pack("!B", len(lb)) + lb
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)
    pkt = header + question
    if len(pkt) > 512:
        raise ValueError("Query too large")
    return pkt

def parse_qname(data: bytes, offset: int):
    i = offset
    labels = []
    while True:
        if i >= len(data):
            raise ValueError("Truncated QNAME")
        l = data[i]
        if l & 0xC0:
            raise ValueError("Compression in QNAME not supported in this demo")
        i += 1
        if l == 0:
            break
        if i + l > len(data):
            raise ValueError("Truncated label")
        labels.append(data[i:i+l].decode("ascii"))
        i += l
    return ".".join(labels), i

def build_dns_response(request: bytes) -> bytes | None:
    try:
        if not request or len(request) < 12 or len(request) > 512:
            return None
        (qid, flags, qd, an, ns, ar) = struct.unpack_from("!HHHHHH", request, 0)
        if qd != 1:
            rflags = 0x8000 | (flags & 0x0100) | 0x0400 | 1
            return struct.pack("!HHHHHH", qid, rflags, 0, 0, 0, 0)
        name, idx = parse_qname(request, 12)
        if idx + 4 > len(request):
            rflags = 0x8000 | (flags & 0x0100) | 0x0400 | 1
            return struct.pack("!HHHHHH", qid, rflags, 0, 0, 0, 0)
        qtype, qclass = struct.unpack_from("!HH", request, idx)
        if qclass != 1:
            rflags = 0x8000 | (flags & 0x0100) | 0x0400 | 4
            return struct.pack("!HHHHHH", qid, rflags, 0, 0, 0, 0)
        rcode = 0
        answer = None
        lname = name.lower()
        if qtype == 1:
            if lname == "example.com":
                answer = socket.inet_aton("93.184.216.34")
            elif lname == "localhost":
                answer = socket.inet_aton("127.0.0.1")
            elif lname == "test.local":
                answer = socket.inet_aton("192.168.1.2")
            else:
                rcode = 3
        else:
            rcode = 4
        rflags = 0x8000 | (flags & 0x0100) | 0x0400 | (rcode & 0xF)
        header = struct.pack("!HHHHHH", qid, rflags, 1, 1 if (answer and rcode == 0) else 0, 0, 0)
        question = request[12:idx+4]
        msg = header + question
        if answer and rcode == 0:
            # NAME pointer to 12
            msg += b"\xC0\x0C" + struct.pack("!HHI", 1, 1, 60) + struct.pack("!H", 4) + answer
        if len(msg) > 512:
            return None
        return msg
    except Exception:
        return None

def run_server(bind_ip: str, port: int, max_requests: int):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((bind_ip, port))
        handled = 0
        while handled < max_requests:
            data, addr = s.recvfrom(512)
            resp = build_dns_response(data)
            if resp:
                s.sendto(resp, addr)
            handled += 1

def parse_a_from_response(resp: bytes) -> str | None:
    if not resp or len(resp) < 12:
        return None
    ancount = struct.unpack_from("!H", resp, 6)[0]
    if ancount < 1:
        return None
    i = 12
    while i < len(resp) and resp[i] != 0:
        l = resp[i]
        if l & 0xC0:
            if i + 1 >= len(resp): return None
            i += 2
            break
        i += 1 + l
    if i >= len(resp): return None
    i += 1
    i += 4
    if i >= len(resp): return None
    if resp[i] & 0xC0:
        i += 2
    else:
        while i < len(resp) and resp[i] != 0:
            l = resp[i]; i += 1 + l
        i += 1
    if i + 10 > len(resp): return None
    rtype, rclass, ttl = struct.unpack_from("!HHI", resp, i); i += 8
    rdlen = struct.unpack_from("!H", resp, i)[0]; i += 2
    if rtype != 1 or rdlen != 4 or i + 4 > len(resp):
        return None
    return ".".join(str(b) for b in resp[i:i+4])

def main():
    bind_ip = "127.0.0.1"
    port = 53536
    t = threading.Thread(target=run_server, args=(bind_ip, port, 5), daemon=True)
    t.start()
    time.sleep(0.2)
    tests = [
        ("example.com", 1),
        ("localhost", 1),
        ("test.local", 1),
        ("unknown.example", 1),
        ("example.com", 28),
    ]
    for idx,(name, qtype) in enumerate(tests, start=1):
        q = build_dns_query(name, qtype, 0x2222+idx)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(2.0)
            c.sendto(q, (bind_ip, port))
            try:
                resp, _ = c.recvfrom(512)
                ip = parse_a_from_response(resp)
                print(f"Py Test {idx} {name} type {qtype} -> {ip if ip else 'NOANSWER'}")
            except socket.timeout:
                print(f"Py Test {idx} timeout")
    t.join(timeout=0.5)

if __name__ == "__main__":
    main()