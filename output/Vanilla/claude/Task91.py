
import socket
import struct
from typing import Dict, Tuple

DNS_RECORDS: Dict[str, str] = {
    "example.com": "93.184.216.34",
    "test.com": "192.168.1.100",
    "localhost": "127.0.0.1",
    "google.com": "142.250.185.46",
    "github.com": "140.82.114.4"
}

def start_dns_server(ip_address: str, port: int) -> None:
    """Start DNS server listening on specified IP and port"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip_address, port))
    print(f"DNS Server listening on {ip_address}:{port}")
    
    data, client_address = sock.recvfrom(512)
    domain_name = parse_dns_query(data)
    print(f"Received query for: {domain_name}")
    
    ip_addr = resolve_dns_record(domain_name)
    response = create_dns_response(data, ip_addr)
    
    sock.sendto(response, client_address)
    print(f"Sent response: {ip_addr}")
    
    sock.close()

def parse_dns_query(query: bytes) -> str:
    """Parse DNS query to extract domain name"""
    domain = []
    pos = 12  # Skip DNS header
    
    while pos < len(query) and query[pos] != 0:
        length = query[pos]
        if length == 0:
            break
        
        pos += 1
        label = query[pos:pos + length].decode('ascii', errors='ignore')
        domain.append(label)
        pos += length
    
    return '.'.join(domain)

def resolve_dns_record(domain_name: str) -> str:
    """Resolve domain name to IP address"""
    return DNS_RECORDS.get(domain_name, "0.0.0.0")

def create_dns_response(query: bytes, ip_address: str) -> bytes:
    """Create DNS response packet"""
    response = bytearray()
    
    # Copy transaction ID
    response.extend(query[0:2])
    
    # Flags: Response, Standard Query, No Error
    response.extend([0x81, 0x80])
    
    # Questions count
    response.extend(query[4:6])
    
    # Answers count
    response.extend([0x00, 0x01])
    
    # Authority and Additional RRs
    response.extend([0x00, 0x00, 0x00, 0x00])
    
    # Copy question section
    pos = 12
    while pos < len(query) and query[pos] != 0:
        response.append(query[pos])
        pos += 1
    response.append(0x00)  # End of domain name
    pos += 1
    
    # Copy QTYPE and QCLASS
    response.extend(query[pos:pos + 4])
    
    # Answer section
    response.extend([0xC0, 0x0C])  # Pointer to domain name
    
    # Type A
    response.extend([0x00, 0x01])
    
    # Class IN
    response.extend([0x00, 0x01])
    
    # TTL (300 seconds)
    response.extend(struct.pack('>I', 300))
    
    # Data length
    response.extend([0x00, 0x04])
    
    # IP Address
    octets = [int(x) for x in ip_address.split('.')]
    response.extend(octets)
    
    return bytes(response)

def create_test_query(domain: str) -> bytes:
    """Create a test DNS query packet"""
    query = bytearray()
    query.extend([0x12, 0x34])  # Transaction ID
    query.extend([0x01, 0x00])  # Flags
    query.extend([0x00, 0x01])  # Questions
    query.extend([0x00, 0x00])  # Answers
    query.extend([0x00, 0x00])  # Authority
    query.extend([0x00, 0x00])  # Additional
    
    labels = domain.split('.')
    for label in labels:
        query.append(len(label))
        query.extend(label.encode('ascii'))
    query.append(0x00)
    
    query.extend([0x00, 0x01])  # Type A
    query.extend([0x00, 0x01])  # Class IN
    
    return bytes(query)

if __name__ == "__main__":
    print("DNS Server Test Cases:")
    print("======================\\n")
    
    # Test Case 1: Parse DNS query
    print("Test 1: Parse DNS Query")
    test_query1 = create_test_query("example.com")
    parsed1 = parse_dns_query(test_query1)
    print(f"Parsed domain: {parsed1}\\n")
    
    # Test Case 2: Resolve DNS record
    print("Test 2: Resolve DNS Record")
    resolved = resolve_dns_record("google.com")
    print(f"Resolved IP: {resolved}\\n")
    
    # Test Case 3: Resolve unknown domain
    print("Test 3: Resolve Unknown Domain")
    unknown_resolved = resolve_dns_record("unknown.com")
    print(f"Resolved IP: {unknown_resolved}\\n")
    
    # Test Case 4: Create DNS response
    print("Test 4: Create DNS Response")
    response = create_dns_response(test_query1, "93.184.216.34")
    print(f"Response created with length: {len(response)}\\n")
    
    # Test Case 5: Multiple domain parsing
    print("Test 5: Parse Multiple Domains")
    domains = ["localhost", "test.com", "github.com"]
    for domain in domains:
        query = create_test_query(domain)
        parsed = parse_dns_query(query)
        ip = resolve_dns_record(parsed)
        print(f"{domain} -> {parsed} -> {ip}")
