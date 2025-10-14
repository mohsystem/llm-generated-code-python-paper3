import socket
import struct

DNS_RECORDS = {
    b"test1.local.": "192.168.1.1",
    b"test2.local.": "192.168.1.2",
    b"example.com.": "93.184.216.34",
    b"my-server.net.": "10.0.0.1",
    b"localhost.": "127.0.0.1",
}
IP_ADDRESS = "127.0.0.1"
PORT = 5353
BUFFER_SIZE = 512

def parse_domain_name(data, offset):
    """Parses a domain name from a DNS query."""
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Check for pointer compression
        if (length & 0xc0) == 0xc0:
            pointer = struct.unpack(">H", data[offset:offset+2])[0]
            pointer &= 0x3fff
            # Recursively parse the pointed-to name and stop current parsing
            labels.append(parse_domain_name(data, pointer)[0])
            offset += 2
            # Since a pointer terminates a name section, we break
            return b".".join(labels) + b'.', offset
        
        offset += 1
        labels.append(data[offset:offset+length])
        offset += length
    
    return b".".join(labels) + b'.', offset

def build_dns_response(data):
    """Parses the DNS query and builds a response."""
    # Transaction ID
    tid = data[:2]

    # Flags (Standard query)
    flags = data[2:4]
    
    # --- Parse Question ---
    # We assume 1 question
    try:
        domain_name, question_offset_end = parse_domain_name(data, 12)
        q_type, q_class = struct.unpack(">HH", data[question_offset_end:question_offset_end+4])
    except (IndexError, struct.error):
        print("Error parsing request: malformed packet.")
        return None

    # We only handle A record (type 1) queries for IN class (class 1)
    if q_type != 1 or q_class != 1:
        print(f"Unsupported query type ({q_type}) or class ({q_class})")
        return None

    ip_address_str = DNS_RECORDS.get(domain_name)
    print(f"Query for: {domain_name.decode('utf-8')}")

    if not ip_address_str:
        print(f"Domain not found: {domain_name.decode('utf-8')}")
        # In a real server, build an NXDOMAIN response
        return None
    
    # --- Build Response ---
    # Response flags (QR=1, Opcode=0, AA=1, RCODE=0 -> 0x8400)
    # 0x8180 for standard response with recursion available
    response_flags = b'\x84\x00'

    # Header: tid, flags, qdcount=1, ancount=1, nscount=0, arcount=0
    header = tid + response_flags + b'\x00\x01\x00\x01\x00\x00\x00\x00'
    
    # Question section (copied from request)
    question = data[12:question_offset_end+4]

    # Answer section
    # Name (pointer to question name at offset 12 -> 0xc00c)
    name_pointer = b'\xc0\x0c'
    # Type=A (1), Class=IN (1), TTL=60, RDLENGTH=4
    answer_meta = struct.pack(">HHILH", 1, 1, 60, 4)
    # RDATA (IP address)
    ip_parts = [int(p) for p in ip_address_str.split('.')]
    ip_data = struct.pack("BBBB", *ip_parts)

    answer = name_pointer + answer_meta + ip_data

    return header + question + answer

def start_dns_server(ip, port):
    """Starts the DNS server on the specified IP and port."""
    try:
        # AF_INET for IPv4, SOCK_DGRAM for UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        print(f"DNS server listening on {ip}:{port}")

        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                print(f"Received request from {addr[0]}")
                
                response = build_dns_response(data)
                if response:
                    sock.sendto(response, addr)
            except Exception as e:
                print(f"An error occurred while handling a request: {e}")

    except OSError as e:
        print(f"Error starting server: {e}")
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == '__main__':
    print("Starting Python DNS Server...")
    print("You can test this server with commands like:")
    print(f"  dig @{IP_ADDRESS} -p {PORT} test1.local")
    print(f"  nslookup example.com {IP_ADDRESS}")
    print("----------------------------------------------")
    start_dns_server(IP_ADDRESS, PORT)