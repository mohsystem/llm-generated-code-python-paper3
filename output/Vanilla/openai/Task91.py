import socket
import struct
import time

def parse_dns_query(data: bytes):
    if len(data) < 12:
        raise ValueError("Invalid DNS packet")
    (id_, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])
    idx = 12
    labels = []
    while idx < len(data):
        ln = data[idx]
        idx += 1
        if ln == 0:
            break
        if idx + ln > len(data):
            raise ValueError("Bad QNAME")
        labels.append(data[idx:idx+ln].decode('utf-8'))
        idx += ln
    if idx + 4 > len(data):
        raise ValueError("Truncated question")
    qtype, qclass = struct.unpack("!HH", data[idx:idx+4])
    return {
        "id": id_,
        "flags": flags,
        "qname": ".".join(labels),
        "qtype": qtype,
        "qclass": qclass,
        "question_end": idx + 4
    }

def ip_to_bytes(ip: str):
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError("Bad IP")
    return bytes(int(p) & 0xFF for p in parts)

def build_dns_response(request: bytes, hosts: dict) -> bytes:
    pq = parse_dns_query(request)
    rd = (pq["flags"] & 0x0100) != 0
    opcode = pq["flags"] & 0x7800
    qn = pq["qname"].lower()
    ip = None
    if pq["qclass"] == 1 and pq["qtype"] == 1:
        ip = hosts.get(qn)
    rcode = 0 if ip else 3
    ancount = 1 if ip else 0
    header = struct.pack("!HHHHHH",
                         pq["id"],
                         0x8000 | opcode | (0x0400) | (0x0100 if rd else 0) | rcode,
                         1, ancount, 0, 0)
    question = request[12:pq["question_end"]]
    ans = b""
    if ip:
        ans = struct.pack("!HHHLH", 0xC00C, 1, 1, 60, 4) + ip_to_bytes(ip)
    return header + question + ans

def build_servfail(request: bytes) -> bytes:
    try:
        pq = parse_dns_query(request)
        rd = (pq["flags"] & 0x0100) != 0
        header = struct.pack("!HHHHHH",
                             pq["id"],
                             0x8000 | (pq["flags"] & 0x7800) | (0x0100 if rd else 0) | 2,
                             1, 0, 0, 0)
        question = request[12:pq["question_end"]]
        return header + question
    except Exception:
        return struct.pack("!HHHHHH", 0, 0x8182, 0, 0, 0, 0)

def build_dns_query(name: str, qtype: int, rd: bool) -> bytes:
    id_ = int(time.time_ns() & 0xFFFF)
    header = struct.pack("!HHHHHH", id_, 0x0100 if rd else 0, 1, 0, 0, 0)
    qname = b"".join(len(label).to_bytes(1, "big") + label.encode("utf-8") for label in name.split(".")) + b"\x00"
    question = struct.pack("!HH", qtype, 1)
    return header + qname + question

def run_udp_dns_server(ip: str, port: int, hosts: dict, max_requests: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    handled = 0
    try:
        while max_requests <= 0 or handled < max_requests:
            data, addr = sock.recvfrom(1500)
            try:
                resp = build_dns_response(data, hosts)
            except Exception:
                resp = build_servfail(data)
            sock.sendto(resp, addr)
            handled += 1
    finally:
        sock.close()

if __name__ == "__main__":
    hosts = {
        "example.com": "93.184.216.34",
        "localhost": "127.0.0.1",
        "github.com": "140.82.113.3",
        "test.local": "10.0.0.1",
        "service.internal": "192.168.1.100"
    }
    tests = ["example.com", "unknown.example", "github.com", "localhost", "test.local"]
    for t in tests:
        q = build_dns_query(t, 1, True)
        r = build_dns_response(q, hosts)
        print("Q:", t, "resp_len:", len(r))
    # Example: run_udp_dns_server("127.0.0.1", 5353, hosts, 5)