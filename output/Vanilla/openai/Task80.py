import socket
import ssl

def create_ipv6_ssl_client(host: str, port: int) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    raw.settimeout(10)
    raw.connect((host, port, 0, 0))
    tls = context.wrap_socket(raw, server_hostname=host)
    return tls

def main():
    hosts = ["google.com", "cloudflare.com", "example.com", "wikipedia.org", "ietf.org"]
    for h in hosts:
        try:
            s = create_ipv6_ssl_client(h, 443)
            print(f"Connected to {h} via IPv6 using {s.version()} {s.cipher()}")
            s.close()
        except Exception as e:
            print(f"Failed to connect to {h}: {e}")

if __name__ == "__main__":
    main()