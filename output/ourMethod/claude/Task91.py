
import socket
import struct
import sys
from typing import Optional, Tuple, Dict

MAX_PACKET_SIZE = 512
MAX_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253
DNS_HEADER_SIZE = 12

DNS_RECORDS: Dict[str, str] = {
    'example.com': '93.184.216.34',
    'test.com': '192.0.2.1',
    'localhost': '127.0.0.1'
}


class DNSRequest:
    def __init__(self, request_id: int, domain: str, valid: bool):
        self.id = request_id
        self.domain = domain
        self.valid = valid


def is_valid_domain_char(c: str) -> bool:
    return c.isalnum() or c in ['-', '_']


def parse_dns_request(data: bytes, length: int) -> DNSRequest:
    if data is None or length < DNS_HEADER_SIZE or length > MAX_PACKET_SIZE:
        return DNSRequest(0, '', False)
    
    try:
        request_id, flags, qd_count = struct.unpack('!HHH', data[0:6])
        
        if (flags & 0x8000) != 0 or qd_count != 1:
            return DNSRequest(request_id, '', False)
        
        domain_parts = []
        position = DNS_HEADER_SIZE
        total_length = 0
        
        while position < length:
            label_len = data[position]
            if label_len == 0:
                position += 1
                break
            
            if label_len > MAX_LABEL_LENGTH:
                return DNSRequest(request_id, '', False)
            
            if (label_len & 0xC0) == 0xC0:
                return DNSRequest(request_id, '', False)
            
            position += 1
            if position + label_len > length:
                return DNSRequest(request_id, '', False)
            
            total_length += label_len + 1
            if total_length > MAX_DOMAIN_LENGTH:
                return DNSRequest(request_id, '', False)
            
            label = data[position:position + label_len].decode('utf-8', errors='strict')
            if not all(is_valid_domain_char(c) for c in label):
                return DNSRequest(request_id, '', False)
            
            domain_parts.append(label)
            position += label_len
        
        if position + 4 > length:
            return DNSRequest(request_id, '', False)
        
        q_type, q_class = struct.unpack('!HH', data[position:position + 4])
        
        if q_type != 1 or q_class != 1:
            return DNSRequest(request_id, '', False)
        
        domain = '.'.join(domain_parts).lower()
        return DNSRequest(request_id, domain, True)
        
    except Exception:
        return DNSRequest(0, '', False)


def create_error_response(request_id: int) -> bytes:
    header = struct.pack('!HHHHHH',
                        request_id,
                        0x8183,  # Response with format error
                        0, 0, 0, 0)
    return header


def create_dns_response(request: DNSRequest, ip_address: Optional[str]) -> bytes:
    if not request.valid or ip_address is None or not ip_address:
        return create_error_response(request.id)
    
    octets = ip_address.split('.')
    if len(octets) != 4:
        return create_error_response(request.id)
    
    try:
        ip_bytes = bytes([int(octet) for octet in octets])
        for octet in ip_bytes:
            if octet < 0 or octet > 255:
                return create_error_response(request.id)
    except (ValueError, OverflowError):
        return create_error_response(request.id)
    
    response = bytearray()
    
    header = struct.pack('!HHHHHH',
                        request.id,
                        0x8180,  # Standard query response, no error
                        1,  # Questions: 1
                        1,  # Answers: 1
                        0,  # Authority RRs: 0
                        0)  # Additional RRs: 0
    response.extend(header)
    
    labels = request.domain.split('.')
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH:
            return create_error_response(request.id)
        response.append(len(label))
        response.extend(label.encode('utf-8'))
    response.append(0)
    
    response.extend(struct.pack('!HH', 1, 1))  # Type A, Class IN
    
    response.extend(struct.pack('!H', 0xC00C))  # Pointer to domain name
    response.extend(struct.pack('!HHIH', 1, 1, 300, 4))  # Type, Class, TTL, Length
    response.extend(ip_bytes)
    
    return bytes(response)


def resolve_domain(domain: str) -> Optional[str]:
    if domain is None or not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return None
    return DNS_RECORDS.get(domain.lower())


def run_dns_server(ip_address: str, port: int, timeout_sec: float) -> None:
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    if timeout_sec <= 0:
        raise ValueError("Timeout must be positive")
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        sock.bind((ip_address, port))
        
        data, addr = sock.recvfrom(MAX_PACKET_SIZE)
        
        request = parse_dns_request(data, len(data))
        
        if request.valid:
            resolved_ip = resolve_domain(request.domain)
            response = create_dns_response(request, resolved_ip)
            sock.sendto(response, addr)
            
    except socket.timeout:
        pass  # Timeout is expected for testing
    except Exception as e:
        raise RuntimeError(f"DNS server error: {e}")
    finally:
        if sock is not None:
            sock.close()


def create_test_dns_request(request_id: int, domain: str) -> bytes:
    request = bytearray()
    
    header = struct.pack('!HHHHHH',
                        request_id,
                        0x0100,  # Standard query
                        1, 0, 0, 0)
    request.extend(header)
    
    labels = domain.split('.')
    for label in labels:
        request.append(len(label))
        request.extend(label.encode('utf-8'))
    request.append(0)
    
    request.extend(struct.pack('!HH', 1, 1))  # Type A, Class IN
    
    return bytes(request)


def main() -> None:
    print("Test Case 1: Parse valid DNS request")
    valid_request = create_test_dns_request(0x1234, 'example.com')
    req1 = parse_dns_request(valid_request, len(valid_request))
    print(f"Valid: {req1.valid}, Domain: {req1.domain}")
    
    print("\\nTest Case 2: Parse invalid DNS request (too short)")
    invalid_request = bytes([0] * 5)
    req2 = parse_dns_request(invalid_request, len(invalid_request))
    print(f"Valid: {req2.valid}")
    
    print("\\nTest Case 3: Resolve known domain")
    ip = resolve_domain('example.com')
    print(f"Resolved IP: {ip}")
    
    print("\\nTest Case 4: Resolve unknown domain")
    unknown_ip = resolve_domain('unknown.com')
    print(f"Resolved IP: {unknown_ip}")
    
    print("\\nTest Case 5: Create DNS response")
    req5 = DNSRequest(0x5678, 'test.com', True)
    response = create_dns_response(req5, '192.0.2.1')
    print(f"Response created, length: {len(response)}")


if __name__ == '__main__':
    main()
