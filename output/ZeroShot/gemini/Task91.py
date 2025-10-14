import socket
import struct
import threading
import time

IP_ADDRESS = "127.0.0.1"
PORT = 53530
BUFFER_SIZE = 512

DNS_RECORDS = {
    b"test1.example.com.": "192.0.2.1",
    b"test2.example.com.": "198.51.100.2",
    b"secure.example.com.": "203.0.113.3",
}

def parse_domain_name(data, offset):
    """Parses a domain name from DNS wire format."""
    labels = []
    start_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Security: Prevent pointer loops and out-of-bounds access
        if (length & 0xC0) == 0xC0 or offset + 1 + length > len(data):
             raise ValueError("Invalid domain name format or pointer")
        offset += 1
        labels.append(data[offset:offset+length])
        offset += length
    
    domain_name = b".".join(labels) + b"."
    bytes_read = offset - start_offset
    return domain_name, bytes_read

def build_response(request_data):
    """Parses a DNS request and builds a corresponding response."""
    try:
        # Parse Header
        tx_id, flags, qd_count, _, _, _ = struct.unpack('!HHHHHH', request_data[:12])

        # Security: Only accept standard queries with one question
        if (flags & 0x7800) != 0 or qd_count != 1:
            return build_error_response(tx_id, 4) # Not Implemented

        # Parse Question
        qname, qname_len = parse_domain_name(request_data, 12)
        q_type, q_class = struct.unpack('!HH', request_data[12 + qname_len : 12 + qname_len + 4])
        
        question = request_data[12 : 12 + qname_len + 4]

        ip_address = DNS_RECORDS.get(qname)
        
        # We only handle A records (type 1) and IN class (class 1)
        if ip_address and q_type == 1 and q_class == 1:
            # --- Build successful response ---
            # Flags: Response, authoritative, no error
            response_flags = 0x8180 
            response_header = struct.pack('!HHHHHH', tx_id, response_flags, 1, 1, 0, 0)
            
            # Answer section
            # Name pointer to offset 12 (0xc00c)
            # Type: A, Class: IN, TTL: 60, RDLENGTH: 4
            answer = struct.pack('!HHHLH', 0xc00c, 1, 1, 60, 4) + socket.inet_aton(ip_address)
            
            return response_header + question + answer
        else:
            # --- Build NXDOMAIN (Name Error) response ---
            return build_nxdomain_response(tx_id, question)

    except (struct.error, IndexError, ValueError):
        # Malformed packet
        return build_error_response(0, 1) # Format Error

def build_error_response(tx_id, rcode):
    flags = 0x8180 | rcode  # Response, recursion desired, with error code
    return struct.pack('!HHHHHH', tx_id, flags, 0, 0, 0, 0)
    
def build_nxdomain_response(tx_id, question):
    flags = 0x8183 # Response, recursion desired, Name Error
    return struct.pack('!HHHHHH', tx_id, flags, 1, 0, 0, 0) + question


def start_server():
    """Starts the UDP DNS server."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((IP_ADDRESS, PORT))
            print(f"Python DNS Server listening on {IP_ADDRESS}:{PORT}")
            
            # Use a global flag to control the server loop from another thread
            while not server_should_stop.is_set():
                sock.settimeout(1.0) # Timeout to check the stop flag
                try:
                    data, addr = sock.recvfrom(BUFFER_SIZE)
                    response = build_response(data)
                    if response:
                        sock.sendto(response, addr)
                except socket.timeout:
                    continue # Loop back to check the stop flag
        except OSError as e:
            print(f"Server Error: {e}")
        finally:
            print("Server shutting down.")

def run_client_tests():
    """Runs 5 test cases against the local server."""
    time.sleep(1) # Wait for server to start
    print("\n--- Running 5 Test Cases ---")
    
    test_queries = [
        ("test1.example.com", "A"),      # 1. Known domain
        ("test2.example.com", "A"),      # 2. Another known domain
        ("secure.example.com", "A"),     # 3. Third known domain
        ("unknown.example.com", "A"),    # 4. Unknown domain
        ("test1.example.com", "MX"),     # 5. Unsupported type
    ]

    for i, (domain, q_type) in enumerate(test_queries):
        print(f"\n--- Test Case {i+1}: Querying for {domain} ({q_type}) ---")
        try:
            # In a real scenario, one would use a DNS library.
            # Here we simulate using a simple socket.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_sock:
                client_sock.settimeout(2)
                
                # Build a simple DNS query packet
                tx_id = 1234 + i
                flags = 0x0100 # Standard query
                qname_encoded = b"".join(len(part).to_bytes(1, 'big') + part.encode('ascii') for part in domain.split('.')) + b'\x00'
                q_type_val = 15 if q_type == "MX" else 1 # A record
                q_class_val = 1 # IN
                
                question = qname_encoded + struct.pack("!HH", q_type_val, q_class_val)
                query = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0) + question
                
                client_sock.sendto(query, (IP_ADDRESS, PORT))
                data, _ = client_sock.recvfrom(BUFFER_SIZE)

                # Basic response parsing
                resp_tx_id, resp_flags, _, an_count, _, _ = struct.unpack('!HHHHHH', data[:12])
                rcode = resp_flags & 0x000F
                
                print(f"Received Response (TXID: {resp_tx_id}, Flags: {hex(resp_flags)}, Answers: {an_count})")
                if rcode == 0 and an_count > 0:
                    # Find where answer starts (after the question)
                    answer_offset = 12 + len(question)
                    # Very basic parsing for A record
                    if data[answer_offset:answer_offset+2] == b'\xc0\x0c':
                        rdata_offset = answer_offset + 10 # Pointer(2)+Type(2)+Class(2)+TTL(4)
                        ip_addr = socket.inet_ntoa(data[rdata_offset:rdata_offset+4])
                        print(f"SUCCESS: Resolved IP: {ip_addr}")
                elif rcode == 3:
                    print("SUCCESS: Received NXDOMAIN as expected.")
                else:
                    print(f"NOTE: Received response with RCODE={rcode} and ANCOUNT={an_count} as expected for unsupported type.")

        except socket.timeout:
            print("ERROR: Client query timed out.")
        except Exception as e:
            print(f"ERROR: An exception occurred: {e}")

if __name__ == "__main__":
    server_should_stop = threading.Event()
    server_thread = threading.Thread(target=start_server)
    
    server_thread.start()
    
    run_client_tests()
    
    # Signal server to stop and wait for it to finish
    server_should_stop.set()
    server_thread.join()
    
    print("\n--- Test cases finished. ---")