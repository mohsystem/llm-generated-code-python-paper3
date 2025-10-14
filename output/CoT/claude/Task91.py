
import socket
import struct
import threading
import time

class Task91:
    DNS_HEADER_SIZE = 12
    MAX_BUFFER_SIZE = 512
    
    def __init__(self):
        self.dns_records = {
            'example.com': '93.184.216.34',
            'test.com': '192.0.2.1',
            'localhost': '127.0.0.1',
            'google.com': '172.217.164.46',
            'github.com': '140.82.121.4'
        }
    
    def start_dns_server(self, ip_address, port):
        """Start UDP DNS server on specified IP and port"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(30.0)
            sock.bind((ip_address, port))
            
            print(f"DNS Server started on {ip_address}:{port}")
            
            while True:
                try:
                    data, client_address = sock.recvfrom(self.MAX_BUFFER_SIZE)
                    
                    if len(data) < self.DNS_HEADER_SIZE:
                        continue
                    
                    response = self.process_dns_request(data)
                    
                    if response and len(response) > 0:
                        sock.sendto(response, client_address)
                        print(f"Response sent to {client_address[0]}:{client_address[1]}")
                        
                except socket.timeout:
                    print("Socket timeout, stopping server...")
                    break
                except Exception as e:
                    print(f"Error processing request: {e}")
                    
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            if sock:
                sock.close()
    
    def process_dns_request(self, request_data):
        """Process incoming DNS request and return response"""
        try:
            if len(request_data) < self.DNS_HEADER_SIZE:
                return None
            
            # Parse DNS header
            header = struct.unpack('!HHHHHH', request_data[:self.DNS_HEADER_SIZE])
            transaction_id = header[0]
            flags = header[1]
            questions = header[2]
            
            if questions <= 0 or questions > 10:
                return None
            
            # Parse question section
            offset = self.DNS_HEADER_SIZE
            domain, offset = self.parse_domain_name(request_data, offset)
            
            if not domain or len(domain) > 253:
                return None
            
            if offset + 4 > len(request_data):
                return None
            
            q_type, q_class = struct.unpack('!HH', request_data[offset:offset+4])
            
            print(f"Query for: {domain} (Type: {q_type})")
            
            # Create response
            return self.create_dns_response(transaction_id, domain, q_type, q_class, request_data)
            
        except Exception as e:
            print(f"Error parsing DNS request: {e}")
            return None
    
    def parse_domain_name(self, data, offset):
        """Parse domain name from DNS packet"""
        domain_parts = []
        original_offset = offset
        jumps = 0
        max_jumps = 10
        
        try:
            while offset < len(data):
                length = data[offset]
                
                if length == 0:
                    offset += 1
                    break
                
                # Check for pointer (compression)
                if (length & 0xC0) == 0xC0:
                    if offset + 1 >= len(data):
                        break
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    if pointer >= len(data) or jumps >= max_jumps:
                        break
                    offset = pointer
                    jumps += 1
                    continue
                
                if length > 63 or offset + length + 1 > len(data):
                    break
                
                label = data[offset + 1:offset + 1 + length].decode('ascii', errors='ignore')
                # Validate label characters
                if all(c.isalnum() or c in '-.' for c in label):
                    domain_parts.append(label)
                
                offset += length + 1
                
                if len('.'.join(domain_parts)) > 253:
                    break
            
            domain = '.'.join(domain_parts)
            return domain, offset if jumps == 0 else original_offset + 2
            
        except Exception as e:
            return None, offset
    
    def create_dns_response(self, transaction_id, domain, q_type, q_class, original_query):
        """Create DNS response packet"""
        try:
            response = bytearray()
            
            # DNS Header
            response.extend(struct.pack('!H', transaction_id))
            response.extend(struct.pack('!H', 0x8180))  # Response, recursion available
            response.extend(struct.pack('!H', 1))  # Questions
            
            ip_address = self.dns_records.get(domain.lower())
            response.extend(struct.pack('!H', 1 if ip_address else 0))  # Answer RRs
            response.extend(struct.pack('!H', 0))  # Authority RRs
            response.extend(struct.pack('!H', 0))  # Additional RRs
            
            # Question section (copy from original)
            question_start = self.DNS_HEADER_SIZE
            question_end = question_start
            
            while question_end < len(original_query) and original_query[question_end] != 0:
                question_end += 1
            question_end += 5  # Include null terminator, type and class
            
            if question_end <= len(original_query):
                response.extend(original_query[question_start:question_end])
            
            # Answer section
            if ip_address:
                response.extend(struct.pack('!H', 0xC00C))  # Pointer to domain name
                response.extend(struct.pack('!H', q_type))  # Type
                response.extend(struct.pack('!H', q_class))  # Class
                response.extend(struct.pack('!I', 300))  # TTL
                response.extend(struct.pack('!H', 4))  # Data length
                
                # IP address
                parts = ip_address.split('.')
                if len(parts) == 4:
                    for part in parts:
                        value = int(part)
                        if 0 <= value <= 255:
                            response.append(value)
            
            return bytes(response)
            
        except Exception as e:
            print(f"Error creating DNS response: {e}")
            return None
    
    def send_dns_query(self, server_ip, server_port, domain):
        """Send DNS query to server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            
            # Build DNS query
            query = bytearray()
            query.extend(struct.pack('!H', 0x1234))  # Transaction ID
            query.extend(struct.pack('!H', 0x0100))  # Standard query
            query.extend(struct.pack('!H', 1))  # Questions
            query.extend(struct.pack('!H', 0))  # Answer RRs
            query.extend(struct.pack('!H', 0))  # Authority RRs
            query.extend(struct.pack('!H', 0))  # Additional RRs
            
            # Domain name
            labels = domain.split('.')
            for label in labels:
                query.append(len(label))
                query.extend(label.encode('ascii'))
            query.append(0)
            
            query.extend(struct.pack('!H', 1))  # Type A
            query.extend(struct.pack('!H', 1))  # Class IN
            
            sock.sendto(bytes(query), (server_ip, server_port))
            
            response, _ = sock.recvfrom(self.MAX_BUFFER_SIZE)
            print(f"Received response for {domain} ({len(response)} bytes)")
            
            sock.close()
            
        except Exception as e:
            print(f"Query error: {e}")


def main():
    print("=== DNS Server Test Cases ===\\n")
    
    dns_server = Task91()
    
    # Start server in separate thread
    server_thread = threading.Thread(
        target=dns_server.start_dns_server,
        args=('127.0.0.1', 5353)
    )
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1)  # Wait for server to start
    
    # Test cases
    test_domains = ['example.com', 'test.com', 'localhost', 'google.com', 'github.com']
    
    for i, domain in enumerate(test_domains, 1):
        print(f"\\nTest Case {i}: Querying {domain}")
        dns_server.send_dns_query('127.0.0.1', 5353, domain)
        time.sleep(0.5)
    
    time.sleep(2)


if __name__ == '__main__':
    main()
