
import socket
import struct
import threading
import time

class Task91:
    DNS_RECORDS = {
        "example.com": "93.184.216.34",
        "test.local": "127.0.0.1",
        "localhost": "127.0.0.1",
        "google.com": "142.250.185.78",
        "github.com": "140.82.121.3"
    }
    
    @staticmethod
    def start_dns_server(ip_address, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((ip_address, port))
            print(f"DNS Server listening on {ip_address}:{port}")
            
            while True:
                data, addr = sock.recvfrom(512)
                response = Task91.process_dns_request(data)
                sock.sendto(response, addr)
                print(f"Response sent to {addr[0]}:{addr[1]}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            sock.close()
    
    @staticmethod
    def process_dns_request(data):
        try:
            transaction_id = struct.unpack('!H', data[0:2])[0]
            
            offset = 12
            domain_name, offset = Task91.parse_domain_name(data, offset)
            query_type, query_class = struct.unpack('!HH', data[offset:offset+4])
            
            print(f"Query for: {domain_name}")
            
            return Task91.build_dns_response(transaction_id, domain_name, query_type, query_class)
        except Exception as e:
            return b''
    
    @staticmethod
    def parse_domain_name(data, offset):
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset+length].decode('ascii'))
            offset += length
        return '.'.join(labels), offset
    
    @staticmethod
    def build_dns_response(transaction_id, domain, query_type, query_class):
        response = bytearray()
        
        response += struct.pack('!H', transaction_id)
        response += struct.pack('!H', 0x8180)
        response += struct.pack('!H', 1)
        response += struct.pack('!H', 1)
        response += struct.pack('!H', 0)
        response += struct.pack('!H', 0)
        
        response += Task91.encode_domain_name(domain)
        response += struct.pack('!HH', query_type, query_class)
        
        response += Task91.encode_domain_name(domain)
        response += struct.pack('!HH', query_type, query_class)
        response += struct.pack('!I', 300)
        
        ip_address = Task91.DNS_RECORDS.get(domain, "0.0.0.0")
        ip_bytes = bytes(map(int, ip_address.split('.')))
        response += struct.pack('!H', 4)
        response += ip_bytes
        
        return bytes(response)
    
    @staticmethod
    def encode_domain_name(domain):
        encoded = bytearray()
        labels = domain.split('.')
        for label in labels:
            encoded.append(len(label))
            encoded += label.encode('ascii')
        encoded.append(0)
        return bytes(encoded)
    
    @staticmethod
    def build_dns_query(domain):
        query = bytearray()
        query += struct.pack('!H', 0x1234)
        query += struct.pack('!H', 0x0100)
        query += struct.pack('!H', 1)
        query += struct.pack('!H', 0)
        query += struct.pack('!H', 0)
        query += struct.pack('!H', 0)
        
        query += Task91.encode_domain_name(domain)
        query += struct.pack('!HH', 1, 1)
        
        return bytes(query)
    
    @staticmethod
    def test_dns_query(domain, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            query = Task91.build_dns_query(domain)
            sock.sendto(query, ('127.0.0.1', port))
            
            print(f"Test: Querying {domain}")
            data, _ = sock.recvfrom(512)
            print(f"Success: Received response for {domain}\\n")
            
            sock.close()
        except Exception as e:
            print(f"Failed: {e}\\n")

if __name__ == "__main__":
    DNS_PORT = 5353
    print("=== DNS Server Test Cases ===\\n")
    
    server_thread = threading.Thread(target=Task91.start_dns_server, args=("127.0.0.1", DNS_PORT))
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1)
    
    test_domains = ["example.com", "test.local", "localhost", "google.com", "github.com"]
    
    for domain in test_domains:
        Task91.test_dns_query(domain, DNS_PORT)
        time.sleep(0.5)
