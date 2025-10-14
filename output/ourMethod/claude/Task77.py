
import ssl
import socket
import re
import os
import tempfile
import secrets
from pathlib import Path
from typing import Tuple

VALID_HOSTNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$')
VALID_FILENAME = re.compile(r'^[a-zA-Z0-9._-]{1,255}$')
MAX_USERNAME_LENGTH = 128
MAX_PASSWORD_LENGTH = 256
FTPS_PORT = 990
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

def validate_hostname(hostname: str) -> bool:
    return hostname is not None and len(hostname) <= 255 and VALID_HOSTNAME.match(hostname) is not None

def validate_username(username: str) -> bool:
    return (username is not None and 0 < len(username) <= MAX_USERNAME_LENGTH 
            and '\\r' not in username and '\\n' not in username)

def validate_password(password: str) -> bool:
    return (password is not None and 0 < len(password) <= MAX_PASSWORD_LENGTH
            and '\\r' not in password and '\\n' not in password)

def validate_filename(filename: str) -> bool:
    return filename is not None and VALID_FILENAME.match(filename) is not None

def sanitize_command(input_str: str) -> str:
    if input_str is None:
        return ""
    return input_str.replace('\\r', '').replace('\\n', '')

def read_response(sock: socket.socket, expected_code: str) -> str:
    response = sock.recv(4096).decode('utf-8', errors='replace')
    if not response.startswith(expected_code):
        raise ValueError(f"Unexpected FTP response: {response}")
    return response

def parse_pasv_response(response: str) -> int:
    start = response.find('(')
    end = response.find(')')
    if start == -1 or end == -1:
        raise ValueError("Invalid PASV response")
    parts = response[start + 1:end].split(',')
    if len(parts) != 6:
        raise ValueError("Invalid PASV response format")
    port = int(parts[4]) * 256 + int(parts[5])
    return port

def download_file(hostname: str, username: str, password: str, filename: str) -> None:
    if not validate_hostname(hostname):
        raise ValueError("Invalid hostname format")
    if not validate_username(username):
        raise ValueError("Invalid username")
    if not validate_password(password):
        raise ValueError("Invalid password")
    if not validate_filename(filename):
        raise ValueError("Invalid filename format")
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs()
    
    with socket.create_connection((hostname, FTPS_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            read_response(ssock, "220")
            
            ssock.sendall(f"USER {sanitize_command(username)}\\r\\n".encode('utf-8'))
            read_response(ssock, "331")
            
            ssock.sendall(f"PASS {sanitize_command(password)}\\r\\n".encode('utf-8'))
            read_response(ssock, "230")
            
            ssock.sendall(b"TYPE I\\r\\n")
            read_response(ssock, "200")
            
            ssock.sendall(b"PASV\\r\\n")
            pasv_response = read_response(ssock, "227")
            data_port = parse_pasv_response(pasv_response)
            
            with socket.create_connection((hostname, data_port)) as data_sock:
                with context.wrap_socket(data_sock, server_hostname=hostname) as data_ssock:
                    ssock.sendall(f"RETR {sanitize_command(filename)}\\r\\n".encode('utf-8'))
                    read_response(ssock, "150")
                    
                    fd, temp_path = tempfile.mkstemp(prefix='ftps_download_', suffix='.tmp')
                    try:
                        bytes_read = 0
                        with os.fdopen(fd, 'wb') as temp_file:
                            while True:
                                data = data_ssock.recv(8192)
                                if not data:
                                    break
                                bytes_read += len(data)
                                if bytes_read > MAX_FILE_SIZE:
                                    raise ValueError("File size exceeds maximum allowed")
                                temp_file.write(data)
                            temp_file.flush()
                            os.fsync(temp_file.fileno())
                        
                        target_path = Path(filename).name
                        Path(temp_path).replace(target_path)
                        
                    except Exception as e:
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
                        raise e
            
            read_response(ssock, "226")
            ssock.sendall(b"QUIT\\r\\n")

def main():
    import sys
    
    if len(sys.argv) != 5:
        print("Usage: python script.py <hostname> <username> <password> <filename>", file=sys.stderr)
        sys.exit(1)
    
    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    filename = sys.argv[4]
    
    try:
        download_file(hostname, username, password, filename)
        print("File downloaded successfully")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
