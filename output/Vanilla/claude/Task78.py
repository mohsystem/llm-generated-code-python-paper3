
from Crypto.PublicKey import RSA
import base64

def generate_rsa_private_key_openssh(key_size):
    try:
        key = RSA.generate(key_size)
        
        # Export in OpenSSH format
        private_key_openssh = key.export_key(format='OpenSSH')
        
        return private_key_openssh.decode('utf-8')
    except Exception as e:
        return f"Error generating key: {str(e)}"

def main():
    print("Test Case 1: 512-bit key")
    key1 = generate_rsa_private_key_openssh(512)
    print(key1[:200] + "...\\n")
    
    print("Test Case 2: 1024-bit key")
    key2 = generate_rsa_private_key_openssh(1024)
    print(key2[:200] + "...\\n")
    
    print("Test Case 3: 2048-bit key")
    key3 = generate_rsa_private_key_openssh(2048)
    print(key3[:200] + "...\\n")
    
    print("Test Case 4: Another 1024-bit key")
    key4 = generate_rsa_private_key_openssh(1024)
    print(key4[:200] + "...\\n")
    
    print("Test Case 5: 512-bit key")
    key5 = generate_rsa_private_key_openssh(512)
    print(key5[:200] + "...\\n")

if __name__ == "__main__":
    main()
