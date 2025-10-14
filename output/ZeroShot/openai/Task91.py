import socket
import struct
import threading
import time

TYPE_A = 1
TYPE_AAAA = 28

def encode_name(name: str) -> bytes:
    if not name:
        return b'\x00'
    out = bytearray()
    for label in name.split('.'):
        if len(label) == 0 or len(label) > 63:
            raise ValueError("Invalid label length")
        lb = label.encode('ascii')
        out.append(len(lb))
        out += lb
    out.append(0)
    return bytes(out)

def decode_name(data: bytes, offset: int) -> (str, int):
    labels = []
    o = offset
    jumped = False
    jump_end = -1
    seen = set()
    while True:
        if o >= len(data):
            raise ValueError("Truncated name")
        length = data[o]
        if length & 0xC0 == 0xC0:
            if o + 1 >= len(data):
                raise ValueError("Bad pointer")
            ptr = ((length & 0x3F) << 8) | data[o+1]
            if ptr in seen:
                raise ValueError("Pointer loop")
            seen.add(ptr)
            if not jumped:
                jump_end = o + 2
                jumped = True
            o = ptr
            continue
        elif length == 0:
            o += 1
            break
        else:
            o += 1
            if o + length > len(data):
                raise ValueError("Label out of range")
            labels.append(data[o:o+length].decode('ascii'))
            o += length
    return '.'.join(labels), (jumped and jump_end) or o

def parse_query(data: bytes):
    if len(data) < 12:
        raise ValueError("Header too short")
    id_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if qd < 1:
        raise ValueError("No questions")
    name, off = decode_name(data, 12)
    if off + 4 > len(data):
        raise ValueError("Truncated question")
    qtype, qclass = struct.unpack("!HH", data[off:off+4])
    return {
        'id': id_,
        'flags': flags,
        'qname': name,
        'qtype': qtype,
        'qclass': qclass,
        'question_end': off + 4
    }

def resolve(qname: str, qtype: int):
    answers = []
    try:
        if qname.lower() == "localhost":
            if qtype == TYPE_A:
                answers.append(socket.inet_aton("127.0.0.1"))
            if qtype == TYPE_AAAA:
                answers.append(socket.inet_pton(socket.AF_INET6, "::1"))
            return answers
        if qtype == TYPE_A:
            infos = socket.getaddrinfo(qname, None, socket.AF_INET, socket.SOCK_DGRAM)
            seen = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    answers.append(socket.inet_aton(addr))
        elif qtype == TYPE_AAAA:
            infos = socket.getaddrinfo(qname, None, socket.AF_INET6, socket.SOCK_DGRAM)
            seen = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    answers.append(socket.inet_pton(socket.AF_INET6, addr))
    except Exception:
        pass
    return answers

def build_response(request: bytes) -> bytes:
    try:
        q = parse_query(request)
        supported = (q['qtype'] in (TYPE_A, TYPE_AAAA)) and (q['qclass'] == 1)
        answers = resolve(q['qname'], q['qtype']) if supported else []
        if not supported:
            rcode = 4
        elif not answers:
            rcode = 3
        else:
            rcode = 0

        flags = 0x8000  # QR=1
        flags |= (q['flags'] & 0x7800)  # opcode
        flags |= (q['flags'] & 0x0100)  # RD copied
        flags |= rcode & 0xF            # rcode

        resp = bytearray()
        resp += struct.pack("!HHHHHH", q['id'], flags, 1, (0 if rcode != 0 else len(answers)), 0, 0)
        resp += request[12:q['question_end']]
        if rcode == 0:
            # name pointer to offset 12
            name_ptr = 0xC00C
            for rd in answers:
                rdata = rd
                rr = struct.pack("!HHI", name_ptr, q['qtype'], 60)
                rr += struct.pack("!H", len(rdata)) + rdata
                rr = rr[:]
                # CLASS IN=1
                rr = rr[:2] + struct.pack("!H", q['qtype']) + struct.pack("!H", 1) + struct.pack("!I", 60) + struct.pack("!H", len(rdata)) + rdata
                # but above doubled; correct approach:
            # Rebuild cleanly
            resp = bytearray()
            resp += struct.pack("!HHHHHH", q['id'], flags, 1, len(answers), 0, 0)
            resp += request[12:q['question_end']]
            for rd in answers:
                resp += struct.pack("!HHHIH", 0xC00C, q['qtype'], 1, 60, len(rd))
                resp += rd

        return bytes(resp[:512])
    except Exception:
        # SERVFAIL
        id_ = 0
        if request and len(request) >= 2:
            id_ = struct.unpack("!H", request[:2])[0]
        return struct.pack("!HHHHHH", id_, 0x8002, 0, 0, 0, 0)

def build_query(id_: int, name: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", id_ & 0xFFFF, 0x0100, 1, 0, 0, 0)
    q = encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + q

def run_dns_server(bind_ip: str, port: int, duration_seconds: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    sock.bind((bind_ip, port))
    end = time.time() + duration_seconds
    try:
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(2048)
                resp = build_response(data)
                if resp:
                    sock.sendto(resp, addr)
            except socket.timeout:
                continue
            except Exception:
                continue
    finally:
        sock.close()

def _rcode_name(rc):
    return {0:"NOERROR",2:"SERVFAIL",3:"NXDOMAIN",4:"NOTIMP"}.get(rc, f"RCODE({rc})")

def main():
    ip, port = "127.0.0.1", 8054
    t = threading.Thread(target=run_dns_server, args=(ip, port, 5), daemon=True)
    t.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1.5)

    names = ["localhost", "localhost", "example.com", "nonexistent.invalid", "example.com"]
    types = [TYPE_A, TYPE_AAAA, TYPE_A, TYPE_A, 16]

    for i in range(5):
        q = build_query(0x2000 + i, names[i], types[i])
        client.sendto(q, (ip, port))
        try:
            resp, _ = client.recvfrom(4096)
            if len(resp) >= 12:
                id_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
                rcode = flags & 0xF
                print(f"Test {i+1}: id={id_} answers={an} rcode={_rcode_name(rcode)}")
            else:
                print(f"Test {i+1}: empty response")
        except socket.timeout:
            print(f"Test {i+1}: timeout")
    client.close()
    t.join()

if __name__ == "__main__":
    main()