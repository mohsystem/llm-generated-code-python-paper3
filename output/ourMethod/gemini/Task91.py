import socket
import struct
from typing import Dict, Tuple, Optional, List

DNS_PORT = 53535  # Use a high port for testing
LISTEN_ADDR = "127.0.0.1"
BUFFER_SIZE = 512

# Simple in-memory DNS record storage
DNS_RECORDS: Dict[bytes, bytes] = {
    b"example.com.": b"\x5d\xb8\xd8\x22",  # 93.184.216.34
    b"test.local.": b"\xc0\xa8\x01\x64",   # 192.168.1.100
    b"hello.world.": b"\x01\x01\x01\x01",  # 1.1.1.1
    b"another.test.": b"\x08\x08\x08\x08", # 8.8.8.8
    b"localhost.": b"\x7f\x00\x00\x01",    # 127.0.0.1
}

def parse_dns_request(data: bytes) -> Tuple[Optional[int], Optional[bytes], bytes, int, int]:
    """
    Parses a DNS request packet.
    Returns (transaction_id, domain_name, full_question, qtype, qclass)
    """
    try:
        # 2. Parse the received data (Header)
        if len(data) < 12:
            print("Request too short for header. Skipping.")
            return None, None, b'', 0, 0
        
        header = data[:12]
        transaction_id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", header)

        # Check if it's a standard query (Opcode is 0)
        if (flags >> 11) & 0xF != 0:
            print("Not a standard query. Skipping.")
            return None, None, b'', 0, 0
        if qdcount != 1:
            print(f"Unsupported question count: {qdcount}. Skipping.")
            return None, None, b'', 0, 0

        # Parse the question section
        offset = 12
        parts: List[bytes] = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1 # Move past null terminator
                break
            # Pointer check
            if (length & 0xc0) == 0xc0:
                print("Pointers in request QNAME are not supported. Skipping.")
                return None, None, b'', 0, 0
            
            offset += 1
            if offset + length > len(data): # Boundary check
                print("Malformed QNAME label (length exceeds buffer). Skipping.")
                return None, None, b'', 0, 0
            
            parts.append(data[offset:offset + length])
            offset += length
        
        domain_name = b".".join(parts) + b'.'

        # Check buffer boundaries for qtype and qclass
        if offset + 4 > len(data):
             print("Packet too short for QTYPE/QCLASS. Skipping.")
             return None, None, b'', 0, 0

        # Extract QTYPE and QCLASS
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        
        full_question = data[12:offset + 4]

        return transaction_id, domain_name, full_question, qtype, qclass
    except (struct.error, IndexError) as e:
        print(f"Error parsing request: {e}")
        return None, None, b'', 0, 0

def build_dns_response(transaction_id: int, question: bytes, domain_name: bytes) -> bytes:
    """Constructs a DNS response packet."""
    # 3. Resolve DNS record
    ip_data = DNS_RECORDS.get(domain_name)

    # 4. Construct the DNS response
    header_part: bytes
    answer_part: bytes = b''
    
    if ip_data:
        # Response with A record
        print(f"Resolved {domain_name.decode('ascii')} to {socket.inet_ntoa(ip_data)}")
        flags = 0x8180  # Standard response, no error
        ancount = 1
        
        answer_part = (
            b'\xc0\x0c' +  # Pointer to domain name at offset 12
            struct.pack("!HHIH", 1, 1, 60, 4) + # Type, Class, TTL, RDLength
            ip_data         # RDATA: the IP address
        )
    else:
        # Response for not found (NXDOMAIN)
        print(f"Could not resolve: {domain_name.decode('ascii')}")
        flags = 0x8183  # Standard response, name error
        ancount = 0
        
    header_part = struct.pack("!HHHHHH", transaction_id, flags, 1, ancount, 0, 0)
    return header_part + question + answer_part

def run_server():
    """Main server function."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((LISTEN_ADDR, DNS_PORT))
            print(f"Starting Python DNS server on {LISTEN_ADDR}:{DNS_PORT}")

            while True:
                # 1. Receive incoming DNS request
                data, addr = sock.recvfrom(BUFFER_SIZE)
                print(f"\nReceived request from {addr}")

                transaction_id, domain_name, question, qtype, qclass = parse_dns_request(data)

                if transaction_id is None or domain_name is None:
                    continue
                
                if qtype != 1 or qclass != 1:
                    print(f"Unsupported QTYPE({qtype}) or QCLASS({qclass}). Skipping.")
                    continue
                
                print(f"Query for: {domain_name.decode('ascii')} (A, IN)")
                response = build_dns_response(transaction_id, question, domain_name)

                # 5. Send the response back to the client
                sock.sendto(response, addr)
                print(f"Sent response to {addr}")

        except OSError as e:
            print(f"Server error: {e}")
        except KeyboardInterrupt:
            print("\nServer shutting down.")

def main():
    """Main entry point with test case explanation."""
    # 5 test cases explained. To test, run this server and use a DNS client like `dig` or `nslookup`.
    # Example commands:
    # 1. dig @127.0.0.1 -p 53535 example.com
    # 2. dig @127.0.0.1 -p 53535 test.local
    # 3. dig @127.0.0.1 -p 53535 hello.world
    # 4. dig @127.0.0.1 -p 53535 not.found
    # 5. dig @127.0.0.1 -p 53535 localhost
    run_server()

if __name__ == "__main__":
    main()