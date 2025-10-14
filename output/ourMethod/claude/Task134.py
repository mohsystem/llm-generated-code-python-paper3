import os
import secrets
from pathlib import Path
from typing import List, Optional  # kept as-is even if Optional is unused
from threading import Lock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Task134:
    MAGIC = b"KEY1"
    VERSION = 1
    SALT_SIZE = 16
    IV_SIZE = 12
    TAG_SIZE = 16
    ITERATIONS = 210000
    KEY_SIZE = 32

    def __init__(self, base_dir: str):
        if not base_dir:
            raise ValueError("Base directory cannot be empty")
        self.base_directory = Path(base_dir).resolve()
        self.base_directory.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()

    def _validate_path(self, filename: str) -> Path:
        if not filename:
            raise ValueError("Filename cannot be empty")
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid filename")

        resolved = (self.base_directory / filename).resolve()
        if not str(resolved).startswith(str(self.base_directory)):
            raise SecurityError("Path traversal detected")

        if resolved.is_symlink():
            raise SecurityError("Symlinks not allowed")

        return resolved

    def _derive_key(self, passphrase: bytes, salt: bytes) -> bytes:
        if not passphrase or len(passphrase) == 0:
            raise ValueError("Passphrase cannot be empty")
        if not salt or len(salt) != self.SALT_SIZE:
            raise ValueError("Invalid salt size")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(passphrase)

    def generate_and_store_key(self, key_name: str, passphrase: str) -> None:
        if not key_name:
            raise ValueError("Key name cannot be empty")
        if not passphrase or len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")

        with self.lock:
            key_path = self._validate_path(key_name + ".key")

            key_material = secrets.token_bytes(32)
            salt = secrets.token_bytes(self.SALT_SIZE)
            iv = secrets.token_bytes(self.IV_SIZE)

            passphrase_bytes = passphrase.encode("utf-8")
            derived_key = self._derive_key(passphrase_bytes, salt)

            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(iv, key_material, None)

            file_data = (
                    self.MAGIC
                    + bytes([self.VERSION])
                    + salt
                    + iv
                    + ciphertext
            )

            temp_path = self.base_directory / f".tmp_{secrets.token_hex(8)}.key"
            try:
                temp_path.write_bytes(file_data)
                os.sync()
                temp_path.replace(key_path)
            finally:
                if temp_path.exists():
                    temp_path.unlink()

    def retrieve_key(self, key_name: str, passphrase: str) -> bytes:
        if not key_name:
            raise ValueError("Key name cannot be empty")
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")

        with self.lock:
            key_path = self._validate_path(key_name + ".key")

            if not key_path.is_file():
                raise FileNotFoundError("Key file not found or not a regular file")

            file_data = key_path.read_bytes()

            min_size = (
                    len(self.MAGIC) + 1 + self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE
            )
            if len(file_data) < min_size:
                raise SecurityError("Invalid key file format")

            offset = 0
            magic = file_data[offset : offset + len(self.MAGIC)]
            offset += len(self.MAGIC)

            if magic != self.MAGIC:
                raise SecurityError("Invalid magic number")

            version = file_data[offset]
            offset += 1

            if version != self.VERSION:
                raise SecurityError("Unsupported version")

            salt = file_data[offset : offset + self.SALT_SIZE]
            offset += self.SALT_SIZE

            iv = file_data[offset : offset + self.IV_SIZE]
            offset += self.IV_SIZE

            ciphertext = file_data[offset:]

            passphrase_bytes = passphrase.encode("utf-8")
            derived_key = self._derive_key(passphrase_bytes, salt)

            aesgcm = AESGCM(derived_key)
            key_material = aesgcm.decrypt(iv, ciphertext, None)

            return key_material

    def delete_key(self, key_name: str) -> bool:
        if not key_name:
            raise ValueError("Key name cannot be empty")

        with self.lock:
            key_path = self._validate_path(key_name + ".key")
            try:
                key_path.unlink()
                return True
            except FileNotFoundError:
                return False

    def list_keys(self) -> List[str]:
        with self.lock:
            keys = []
            for entry in self.base_directory.glob("*.key"):
                if entry.is_file():
                    keys.append(entry.stem)
            return keys


class SecurityError(Exception):
    pass


def main():
    import shutil
    import tempfile

    temp_dir = tempfile.mkdtemp(prefix="keymanager_")
    try:
        key_manager = Task134(temp_dir)

        print("Test 1: Generate and retrieve key")
        passphrase1 = "SecurePassphrase123!"
        key_manager.generate_and_store_key("testkey1", passphrase1)
        key1 = key_manager.retrieve_key("testkey1", passphrase1)
        print(f"Key retrieved successfully: {len(key1) == 32}")

        print("Test 2: List keys")
        passphrase2 = "AnotherSecure456!"
        key_manager.generate_and_store_key("testkey2", passphrase2)
        keys = key_manager.list_keys()
        print(f"Keys found: {len(keys)}")

        print("Test 3: Invalid passphrase")
        wrong_pass = "WrongPassphrase789!"
        try:
            key_manager.retrieve_key("testkey1", wrong_pass)
            print("ERROR: Should have failed")
        except Exception:
            print("Correctly rejected wrong passphrase")

        print("Test 4: Delete key")
        deleted = key_manager.delete_key("testkey1")
        print(f"Key deleted: {deleted}")

        print("Test 5: Path traversal prevention")
        try:
            key_manager.generate_and_store_key("../etc/passwd", "test123456789!")
            print("ERROR: Should have prevented path traversal")
        except ValueError:
            print("Path traversal correctly prevented")

    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
