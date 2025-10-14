from typing import ByteString
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_key_aes_cbc(key_to_encrypt: ByteString, cipher_key: ByteString, iv: ByteString) -> bytes:
    if len(cipher_key) not in (16, 24, 32):
        raise ValueError("cipher_key must be 16, 24, or 32 bytes")
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    cipher = AES.new(bytes(cipher_key), AES.MODE_CBC, bytes(iv))
    return cipher.encrypt(pad(bytes(key_to_encrypt), AES.block_size))

def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)

def bytes_to_hex(b: ByteString) -> str:
    return bytes(b).hex()

if __name__ == "__main__":
    # Test case 1
    key1 = hex_to_bytes("00112233445566778899aabbccddeeff")
    ck1 = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    iv1 = hex_to_bytes("101112131415161718191a1b1c1d1e1f")
    ct1 = encrypt_key_aes_cbc(key1, ck1, iv1)
    print(bytes_to_hex(ct1))

    # Test case 2
    key2 = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    ck2 = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
    iv2 = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    ct2 = encrypt_key_aes_cbc(key2, ck2, iv2)
    print(bytes_to_hex(ct2))

    # Test case 3
    key3 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ck3 = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv3 = hex_to_bytes("0f0e0d0c0b0a09080706050403020100")
    ct3 = encrypt_key_aes_cbc(key3, ck3, iv3)
    print(bytes_to_hex(ct3))

    # Test case 4
    key4 = hex_to_bytes("00112233445566778899aabbccddeeff00112233")
    ck4 = hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    iv4 = hex_to_bytes("1f1e1d1c1b1a19181716151413121110")
    ct4 = encrypt_key_aes_cbc(key4, ck4, iv4)
    print(bytes_to_hex(ct4))

    # Test case 5
    key5 = hex_to_bytes("000102030405060708090a0b0c0d0e")
    ck5 = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    iv5 = hex_to_bytes("aabbccddeeff00112233445566778899")
    ct5 = encrypt_key_aes_cbc(key5, ck5, iv5)
    print(bytes_to_hex(ct5))