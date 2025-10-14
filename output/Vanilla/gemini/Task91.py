import socket
import struct
import threading
import time

IP = "127.0.0.1"
PORT = 5353
SERVER_RUNNING = True

DNS_RECORDS = {
    b"test1.dns.local.": "1.1.1.1",
    b"test2.dns.local.": "2.2.2.2",
    b"test3.dns.local.": "3.3.3.3",
}

def parse_domain_name(data, offset):
    """Parses a domain name from a DNS query."""
    labels = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length])
        offset += length
    
    # Return the domain name and the offset of the next section
    return b".".join(labels) + b".", offset

def build_dns_response(request_data):
    """Builds a DNS response packet."""
    # Unpack header
    trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", request_data[:12])
    
    # Parse question section
    domain_name, question_end_offset = parse_domain_name(request_data, 12)
    qtype, qclass = struct.unpack("!HH", request_data[question_end_offset:question_end_offset + 4])
    
    ip_address = DNS_RECORDS.get(domain_name)
    
    if ip_address and qtype == 1 and qclass == 1: # A, IN
        # Found
        response_flags = 0x8180 # Standard response, no error
        ancount = 1
        
        # Header + Question
        response = request_data[:question_end_offset + 4]
        
        # Answer
        response += struct.pack("!HHHLH", 
                                0xc00c,  # Pointer to domain name at offset 12
                                1,       # Type A
                                1,       # Class IN
                                60,      # TTL
                                4)       # RDLENGTH
        response += socket.inet_aton(ip_address)
        
        # Update header
        response = struct.pack("!HHHHHH", trans_id, response_flags, qdcount, ancount, nscount, arcount) + response[12:]
    else:
        # Not Found (NXDOMAIN)
        response_flags = 0x8183 # Standard response, NXDOMAIN
        ancount = 0
        
        # Header + Question
        response = request_data[:question_end_offset + 4]
        
        # Update header
        response = struct.pack("!HHHHHH", trans_id, response_flags, qdcount, ancount, nscount, arcount) + response[12:]

    return response

def run_server():
    """Runs the UDP DNS server."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((IP, PORT))
        s.settimeout(1.0) # To allow checking SERVER_RUNNING flag
        print(f"Python DNS Server listening on {IP}:{PORT}")
        
        global SERVER_RUNNING
        while SERVER_RUNNING:
            try:
                data, addr = s.recvfrom(512)
                response = build_dns_response(data)
                s.sendto(response, addr)
            except socket.timeout:
                continue
    print("Python DNS Server stopped.")

def run_client_test(hostname):
    """Runs a single client test case."""
    print(f"\n--- Testing: {hostname} ---")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2.0)
        
        # Build query
        trans_id = 0x1234
        flags = 0x0100 # Standard query
        query = struct.pack("!HHHHHH", trans_id, flags, 1, 0, 0, 0)
        
        # Encode domain name
        for label in hostname.encode('ascii').split(b'.'):
            query += struct.pack("!B", len(label)) + label
        query += b'\x00' # End of name
        query += struct.pack("!HH", 1, 1) # QTYPE: A, QCLASS: IN
        
        try:
            s.sendto(query, (IP, PORT))
            data, _ = s.recvfrom(512)
            
            # Unpack response
            _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
            print(f"Query sent for: {hostname}")
            print(f"Flags: {flags:#06x}")
            
            if flags & 0x000F == 3: # NXDOMAIN
                print("Response: NXDOMAIN (Not Found)")
            elif ancount > 0:
                # Assuming the answer is at the end
                ip_raw = data[-4:]
                ip_addr = socket.inet_ntoa(ip_raw)
                print(f"Resolved IP: {ip_addr}")
            else:
                 print("Response received, but no answer record.")

        except socket.timeout:
            print("Request timed out.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    
    # Give the server a moment to start
    time.sleep(0.5)

    # 5 Test cases
    run_client_test("test1.dns.local")
    run_client_test("test2.dns.local")
    run_client_test("unknown.dns.local")
    run_client_test("test3.dns.local")
    run_client_test("another.unknown.com")
    
    # Signal server to stop and wait for it
    SERVER_RUNNING = False
    server_thread.join()
    print("\nAll tests completed.")