
import socket
import secrets
import os
from typing import Dict, Optional, Set
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import threading
import time

MAGIC = b"RMI1"
VERSION = 1
SALT_SIZE = 16
IV_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 210000
MAX_PAYLOAD_SIZE = 1048576
MAX_METHOD_NAME_LENGTH = 128
MAX_OBJECT_ID_LENGTH = 64


class SecureRemoteObject:
    def __init__(self) -> None:
        self._storage: Dict[str, str] = {}
        self._allowed_methods: Set[str] = {"get", "set", "remove", "exists"}
        self._lock = threading.Lock()
    
    def invoke(self, method: str, object_id: str, value: Optional[str] = None) -> str:
        if method is None or object_id is None:
            return "ERROR: null parameters"
        
        if len(method) > MAX_METHOD_NAME_LENGTH or len(object_id) > MAX_OBJECT_ID_LENGTH:
            return "ERROR: parameter too long"
        
        if method not in self._allowed_methods:
            return "ERROR: method not allowed"
        
        with self._lock:
            if method == "get":
                result = self._storage.get(object_id)
                return result if result is not None else "NULL"
            elif method == "set":
                if value is None or len(value) > 1024:
                    return "ERROR: invalid value"
                self._storage[object_id] = value
                return "OK"
            elif method == "remove":
                self._storage.pop(object_id, None)
                return "OK"
            elif method == "exists":
                return "TRUE" if object_id in self._storage else "FALSE"
            else:
                return "ERROR: unknown method"


class SecureProtocol:
    def __init__(self, passphrase: str) -> None:
        if not passphrase or len(passphrase) < 12:
            raise ValueError("Passphrase too short")
        
        salt = secrets.token_bytes(SALT_SIZE)
        self._key = self._derive_key(passphrase, salt)
        self._aesgcm = AESGCM(self._key)
    
    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        return kdf.derive(passphrase.encode('utf-8'))
    
    def encrypt(self, plaintext: str) -> bytes:
        if not plaintext or len(plaintext) > MAX_PAYLOAD_SIZE:
            raise ValueError("Invalid plaintext")
        
        iv = secrets.token_bytes(IV_SIZE)
        plain_bytes = plaintext.encode('utf-8')
        ciphertext = self._aesgcm.encrypt(iv, plain_bytes, None)
        
        return MAGIC + bytes([VERSION]) + iv + ciphertext
    
    def decrypt(self, encrypted: bytes) -> str:
        if not encrypted or len(encrypted) < len(MAGIC) + 1 + IV_SIZE + TAG_SIZE:
            raise ValueError("Invalid encrypted data")
        
        offset = 0
        magic = encrypted[offset:offset + len(MAGIC)]
        offset += len(MAGIC)
        
        if magic != MAGIC:
            raise SecurityError("Invalid magic")
        
        version = encrypted[offset]
        offset += 1
        
        if version != VERSION:
            raise SecurityError("Invalid version")
        
        iv = encrypted[offset:offset + IV_SIZE]
        offset += IV_SIZE
        
        ciphertext = encrypted[offset:]
        
        plain_bytes = self._aesgcm.decrypt(iv, ciphertext, None)
        return plain_bytes.decode('utf-8')


class SecurityError(Exception):
    pass


class RemoteServer:
    def __init__(self, port: int, passphrase: str) -> None:
        if port < 1024 or port > 65535:
            raise ValueError("Invalid port")
        
        self._port = port
        self._remote_object = SecureRemoteObject()
        self._protocol = SecureProtocol(passphrase)
    
    def start(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('localhost', self._port))
                server_socket.listen(1)
                server_socket.settimeout(30.0)
                
                client_socket, _ = server_socket.accept()
                with client_socket:
                    client_socket.settimeout(10.0)
                    self._handle_client(client_socket)
        except Exception:
            pass
    
    def _handle_client(self, client_socket: socket.socket) -> None:
        try:
            request = client_socket.recv(MAX_PAYLOAD_SIZE)
            
            if not request or len(request) > MAX_PAYLOAD_SIZE:
                return
            
            decrypted = self._protocol.decrypt(request)
            parts = decrypted.split('|', 2)
            
            if len(parts) < 2:
                return
            
            method = parts[0]
            object_id = parts[1]
            value = parts[2] if len(parts) > 2 else None
            
            result = self._remote_object.invoke(method, object_id, value)
            response = self._protocol.encrypt(result)
            client_socket.sendall(response)
        except Exception:
            pass


class RemoteClient:
    def __init__(self, host: str, port: int, passphrase: str) -> None:
        if not host or port < 1024 or port > 65535:
            raise ValueError("Invalid connection parameters")
        
        self._host = host
        self._port = port
        self._protocol = SecureProtocol(passphrase)
    
    def call(self, method: str, object_id: str, value: Optional[str] = None) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10.0)
                sock.connect((self._host, self._port))
                
                request = method + '|' + object_id + ('|' + value if value else '')
                encrypted = self._protocol.encrypt(request)
                
                sock.sendall(encrypted)
                response = sock.recv(MAX_PAYLOAD_SIZE)
                
                if not response:
                    return "ERROR: no response"
                
                return self._protocol.decrypt(response)
        except Exception:
            return "ERROR: connection failed"


def main() -> None:
    try:
        passphrase = "TestPassphrase123!@#"
        test_port = 9999
        
        def run_server() -> None:
            try:
                server = RemoteServer(test_port, passphrase)
                server.start()
            except Exception:
                pass
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        time.sleep(1)
        
        client = RemoteClient("localhost", test_port, passphrase)
        
        print(f"Test 1 - Set value: {client.call('set', 'key1', 'value1')}")
        print(f"Test 2 - Get value: {client.call('get', 'key1')}")
        print(f"Test 3 - Check exists: {client.call('exists', 'key1')}")
        print(f"Test 4 - Remove value: {client.call('remove', 'key1')}")
        print(f"Test 5 - Get removed: {client.call('get', 'key1')}")
        
        server_thread.join(timeout=2.0)
    except Exception:
        print("Test execution failed", file=os.sys.stderr)


if __name__ == "__main__":
    main()
