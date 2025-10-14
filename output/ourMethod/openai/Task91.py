import socket
import threading
from typing import Dict, Optional, Tuple, List
import time

DNS_HEADER_LEN = 12
MAX_DNS_UDP_SIZE = 512
TYPE_A = 1
CLASS_IN = 1

def is_valid_hostname(name: str) -> bool:
    if not isinstance(name, str):
        return False
    n = name.strip()
    if not n or len(n) > 253:
        return False
    labels = n.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        for ch in label:
            if not (ch.isalnum() or ch in "-_"):
                return False
    return True

def encode_qname(hostname: str) -> bytes:
    if not is_valid_hostname(hostname):
        raise ValueError("Invalid hostname")
    parts = hostname.split(".")
    out = bytearray()
    for p in parts:
        b = p.encode("ascii")
        if len(b) == 0 or len(b) > 63:
            raise ValueError("Invalid label length")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    if len(out) > 255:
        raise ValueError("QName too long")
    return bytes(out)

def decode_qname(data: bytes, offset: int) -> Tuple[str, int]:
    if offset >= len(data):
        raise ValueError("Out of bounds")
    labels: List[str] = []
    idx = offset
    total_len = 0
    while True:
        if idx >= len(data):
            raise ValueError("Out of bounds")
        ln = data[idx]
        idx += 1
        if ln & 0xC0:
            raise ValueError("Compression not allowed in question")
        if ln == 0:
            break
        if ln > 63:
            raise ValueError("Label too long")
        if idx + ln > len(data):
            raise ValueError("Label exceeds packet")
        label = data[idx:idx+ln].decode("ascii", errors="strict")
        if not label or len(label) > 63:
            raise ValueError("Invalid label")
        for ch in label:
            if not (ch.isalnum() or ch in "-_"):
                raise ValueError("Invalid char in label")
        labels.append(label)
        idx += ln
        total_len += ln + 1
        if total_len > 255:
            raise ValueError("QName too long")
    name = ".".join(labels)
    if not name:
        raise ValueError("Empty name")
    return name, idx

def u16(b: bytes, off: int) -> int:
    if off + 2 > len(b):
        raise ValueError("Out of bounds")
    return (b[off] << 8) | b[off+1]

def put_u16(out: bytearray, v: int) -> None:
    out.append((v >> 8) & 0xFF)
    out.append(v & 0xFF)

def put_u32(out: bytearray, v: int) -> None:
    out.append((v >> 24) & 0xFF)
    out.append((v >> 16) & 0xFF)
    out.append((v >> 8) & 0xFF)
    out.append(v & 0xFF)

def build_dns_query(hostname: str, qtype: int, qid: int, rd: bool = True) -> bytes:
    if not is_valid_hostname(hostname):
        raise ValueError("Invalid hostname")
    out = bytearray()
    put_u16(out, qid & 0xFFFF)
    flags = 0
    if rd:
        flags |= 0x0100
    put_u16(out, flags)
    put_u16(out, 1)  # QDCOUNT
    put_u16(out, 0)  # ANCOUNT
    put_u16(out, 0)  # NSCOUNT
    put_u16(out, 0)  # ARCOUNT
    out.extend(encode_qname(hostname))
    put_u16(out, qtype & 0xFFFF)
    put_u16(out, CLASS_IN)
    if len(out) > MAX_DNS_UDP_SIZE:
        raise ValueError("Query too large")
    return bytes(out)

class ParsedResponse:
    def __init__(self, qid: int, rcode: int, ancount: int, answer_ipv4: Optional[str]):
        self.id = qid
        self.rcode = rcode
        self.ancount = ancount
        self.answer_ipv4 = answer_ipv4

def parse_dns_response(data: bytes) -> ParsedResponse:
    if len(data) < DNS_HEADER_LEN:
        raise ValueError("Short packet")
    qid = u16(data, 0)
    flags = u16(data, 2)
    rcode = flags & 0x000F
    qd = u16(data, 4)
    an = u16(data, 6)
    off = DNS_HEADER_LEN
    for _ in range(qd):
        name, off = decode_qname(data, off)
        if off + 4 > len(data):
            raise ValueError("Truncated question")
        off += 4
    ip_answer: Optional[str] = None
    if an > 0:
        # Skip name (likely pointer)
        if off >= len(data):
            raise ValueError("Truncated answer")
        ln = data[off]
        if (ln & 0xC0) == 0xC0:
            off += 2
        else:
            while True:
                if off >= len(data):
                    raise ValueError("Truncated name")
                ln = data[off]
                off += 1
                if ln == 0:
                    break
                if (ln & 0xC0) != 0 or off + ln > len(data):
                    raise ValueError("Invalid name in answer")
                off += ln
        atype = u16(data, off); off += 2
        aclass = u16(data, off); off += 2
        off += 4  # TTL
        rdlen = u16(data, off); off += 2
        if off + rdlen > len(data):
            raise ValueError("Truncated rdata")
        if atype == TYPE_A and aclass == CLASS_IN and rdlen == 4:
            b = data[off:off+4]
            ip_answer = f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"
    return ParsedResponse(qid, rcode, an, ip_answer)

class DnsServer(threading.Thread):
    def __init__(self, ip: str, port: int, records: Dict[str, str]):
        super().__init__(daemon=True)
        if not isinstance(ip, str):
            raise ValueError("ip must be string")
        if not (0 <= port <= 65535):
            raise ValueError("Port out of range")
        try:
            self.bind_addr = ip
            socket.inet_pton(socket.AF_INET, ip)
            self.af = socket.AF_INET
        except OSError:
            # Allow IPv6 localhost as well
            self.af = socket.AF_INET6
            socket.inet_pton(socket.AF_INET6, ip)
        # Build validated A records (IPv4 only)
        self.a_records: Dict[str, bytes] = {}
        for k, v in (records or {}).items():
            if not is_valid_hostname(k):
                continue
            try:
                b = socket.inet_pton(socket.AF_INET, v)
                self.a_records[k.lower()] = b
            except OSError:
                # skip non-IPv4
                pass
        self.req_port = port
        self.running = threading.Event()
        self.sock: Optional[socket.socket] = None

    def run(self) -> None:
        with socket.socket(self.af, socket.SOCK_DGRAM) as s:
            self.sock = s
            s.bind((self.bind_addr, self.req_port))
            s.settimeout(0.5)
            self.running.set()
            while self.running.is_set():
                try:
                    data, addr = s.recvfrom(MAX_DNS_UDP_SIZE)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    resp = self.handle_request(data)
                    if resp:
                        s.sendto(resp, addr)
                except Exception:
                    # Fail closed; do not send anything on unexpected errors
                    pass

    def stop(self) -> None:
        self.running.clear()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def server_port(self) -> int:
        if not self.sock:
            return -1
        try:
            return self.sock.getsockname()[1]
        except Exception:
            return -1

    def handle_request(self, data: bytes) -> Optional[bytes]:
        if len(data) < DNS_HEADER_LEN:
            return None
        try:
            qid = u16(data, 0)
            flags = u16(data, 2)
            qr = (flags >> 15) & 1
            opcode = (flags >> 11) & 0xF
            rd = (flags >> 8) & 1
            qd = u16(data, 4)
            if qr != 0 or opcode != 0 or qd < 1:
                return self.build_error_response(qid, rd, 1, data)  # FORMERR
            name, off = decode_qname(data, DNS_HEADER_LEN)
            if off + 4 > len(data):
                return self.build_error_response(qid, rd, 1, data)
            qtype = u16(data, off); off += 2
            qclass = u16(data, off); off += 2
            if qclass != CLASS_IN:
                return self.build_error_response(qid, rd, 4, data)  # Not Implemented
            if qtype != TYPE_A:
                return self.build_error_response(qid, rd, 4, data)  # Not Implemented
            ipb = self.a_records.get(name.lower())
            if not ipb:
                return self.build_error_response(qid, rd, 3, data)  # NXDOMAIN
            return self.build_a_response(qid, rd, data, name, ipb)
        except Exception:
            try:
                qid = u16(data, 0) if len(data) >= 2 else 0
                rd = (u16(data, 2) >> 8) & 1 if len(data) >= 4 else 0
                return self.build_error_response(qid, rd, 1, data)
            except Exception:
                return None

    def build_error_response(self, qid: int, rd: int, rcode: int, request: bytes) -> bytes:
        out = bytearray()
        put_u16(out, qid & 0xFFFF)
        flags = 0x8000  # QR=1
        flags |= 0x0400  # AA=1
        if rd:
            flags |= 0x0100
        flags |= (rcode & 0xF)
        put_u16(out, flags)
        qdcount = 0
        try:
            if len(request) >= DNS_HEADER_LEN and u16(request, 4) >= 1:
                qdcount = 1
        except Exception:
            qdcount = 0
        put_u16(out, qdcount)
        put_u16(out, 0)  # ANCOUNT
        put_u16(out, 0)  # NSCOUNT
        put_u16(out, 0)  # ARCOUNT
        if qdcount == 1:
            try:
                name, off = decode_qname(request, DNS_HEADER_LEN)
                out.extend(request[DNS_HEADER_LEN:off])
                put_u16(out, u16(request, off))
                put_u16(out, u16(request, off+2))
            except Exception:
                pass
        return bytes(out)

    def build_a_response(self, qid: int, rd: int, request: bytes, name: str, ipb: bytes) -> bytes:
        # Build header
        out = bytearray()
        put_u16(out, qid & 0xFFFF)
        flags = 0x8000 | 0x0400  # QR=1, AA=1
        if rd:
            flags |= 0x0100
        put_u16(out, flags)
        put_u16(out, 1)  # QDCOUNT
        put_u16(out, 1)  # ANCOUNT
        put_u16(out, 0)  # NSCOUNT
        put_u16(out, 0)  # ARCOUNT
        # Question copied
        qname, off = decode_qname(request, DNS_HEADER_LEN)
        out.extend(request[DNS_HEADER_LEN:off])
        put_u16(out, u16(request, off))
        put_u16(out, u16(request, off+2))
        # Answer with name pointer to 0x0C
        out.append(0xC0); out.append(0x0C)
        put_u16(out, TYPE_A)
        put_u16(out, CLASS_IN)
        put_u32(out, 60)  # TTL
        put_u16(out, 4)   # RDLENGTH
        out.extend(ipb)
        return bytes(out)

def send_dns_query_and_receive(server_ip: str, server_port: int, name: str, qtype: int, qid: int) -> ParsedResponse:
    if not is_valid_hostname(name):
        raise ValueError("Invalid name")
    if not (0 < server_port <= 65535):
        raise ValueError("Invalid port")
    fam = socket.AF_INET
    try:
        socket.inet_pton(socket.AF_INET, server_ip)
        fam = socket.AF_INET
        addr = (server_ip, server_port)
    except OSError:
        socket.inet_pton(socket.AF_INET6, server_ip)
        fam = socket.AF_INET6
        addr = (server_ip, server_port, 0, 0)
    query = build_dns_query(name, qtype, qid, rd=True)
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(1.0)
        s.sendto(query, addr)
        data, _ = s.recvfrom(MAX_DNS_UDP_SIZE)
        return parse_dns_response(data)

def main() -> None:
    records = {
        "example.com": "93.184.216.34",
        "localhost": "127.0.0.1",
        "test.local": "10.0.0.123",
        "a.b.c": "192.0.2.1",
    }
    server = DnsServer("127.0.0.1", 0, records)
    server.start()
    # Wait until bound
    for _ in range(20):
        if server.server_port() > 0:
            break
        time.sleep(0.05)
    port = server.server_port()
    print(f"DNS server listening on 127.0.0.1:{port}")

    try:
        # Test 1: A example.com
        r1 = send_dns_query_and_receive("127.0.0.1", port, "example.com", TYPE_A, 0x1111)
        print(f"Test1: id={r1.id} rcode={r1.rcode} ancount={r1.ancount} A={r1.answer_ipv4}")

        # Test 2: A localhost
        r2 = send_dns_query_and_receive("127.0.0.1", port, "localhost", TYPE_A, 0x2222)
        print(f"Test2: id={r2.id} rcode={r2.rcode} ancount={r2.ancount} A={r2.answer_ipv4}")

        # Test 3: A unknown -> NXDOMAIN
        try:
            r3 = send_dns_query_and_receive("127.0.0.1", port, "unknown.example", TYPE_A, 0x3333)
            print(f"Test3: id={r3.id} rcode={r3.rcode} ancount={r3.ancount} A={r3.answer_ipv4}")
        except Exception as ex:
            print(f"Test3: exception {ex}")

        # Test 4: AAAA example.com -> Not Implemented
        TYPE_AAAA = 28
        r4 = send_dns_query_and_receive("127.0.0.1", port, "example.com", TYPE_AAAA, 0x4444)
        print(f"Test4: id={r4.id} rcode={r4.rcode} ancount={r4.ancount} A={r4.answer_ipv4}")

        # Test 5: Malformed query (too short) -> expect no response or FORMERR
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.75)
            s.sendto(b"\x00\x01\x02", ("127.0.0.1", port))
            try:
                data, _ = s.recvfrom(MAX_DNS_UDP_SIZE)
                r5 = parse_dns_response(data)
                print(f"Test5: id={r5.id} rcode={r5.rcode} ancount={r5.ancount} A={r5.answer_ipv4}")
            except socket.timeout:
                print("Test5: no response (expected for malformed)")
    finally:
        server.stop()

if __name__ == "__main__":
    main()