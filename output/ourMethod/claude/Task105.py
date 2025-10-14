
import ssl
import socket
import urllib.request
import urllib.error
from typing import Optional
from datetime import datetime
import certifi

def connect_securely(url: str) -> str:
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS URLs are allowed")
    
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    
    try:
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'SecureClient/1.0')
        
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            sock = response.fp.raw._sock
            
            if isinstance(sock, ssl.SSLSocket):
                cipher = sock.cipher()
                if cipher:
                    protocol_version = cipher[1]
                    if protocol_version not in ["TLSv1.2", "TLSv1.3"]:
                        raise ssl.SSLError(f"Insecure protocol: {protocol_version}")
                
                cert = sock.getpeercert()
                if not cert:
                    raise ssl.SSLError("No certificate received from server")
                
                validate_certificate(cert, url)
            
            response_data = response.read(10240).decode('utf-8', errors='ignore')
            status_code = response.getcode()
            
            return f"Response Code: {status_code}\\n{response_data[:500]}"
            
    except urllib.error.URLError as e:
        raise RuntimeError(f"Secure connection failed: {str(e)}")
    except ssl.SSLError as e:
        raise RuntimeError(f"SSL error: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Connection error: {str(e)}")


def validate_certificate(cert: dict, url: str) -> None:
    if 'notAfter' in cert:
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        if datetime.now() > not_after:
            raise ssl.SSLError("Certificate has expired")
    
    if 'notBefore' in cert:
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        if datetime.now() < not_before:
            raise ssl.SSLError("Certificate not yet valid")
    
    hostname = url.split("//")[1].split("/")[0].split(":")[0]
    
    san_list = []
    if 'subjectAltName' in cert:
        san_list = [name for type_name, name in cert['subjectAltName'] if type_name == 'DNS']
    
    if not san_list:
        subject = dict(x[0] for x in cert.get('subject', []))
        san_list = [subject.get('commonName', '')]
    
    hostname_valid = False
    for san in san_list:
        if san.lower() == hostname.lower():
            hostname_valid = True
            break
    
    if not hostname_valid:
        raise ssl.SSLError(f"Hostname {hostname} doesn't match certificate")


def main() -> None:
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.cloudflare.com",
        "https://www.mozilla.org"
    ]
    
    for url in test_urls:
        try:
            print(f"Testing connection to: {url}")
            result = connect_securely(url)
            print(f"Success: {result[:100]}...\\n")
        except Exception as e:
            print(f"Failed: {str(e)}\\n")


if __name__ == "__main__":
    main()
