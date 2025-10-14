import hashlib
import os
import tempfile
import urllib.request
import urllib.parse

# Downloads an EXE securely from Google Drive/Googleusercontent over HTTPS with size cap and SHA-256 verification.
# Returns absolute file path on success; raises Exception on failure.
def download_exe_from_google_drive(url: str, expected_sha256_hex: str, max_bytes: int = 50 * 1024 * 1024) -> str:
    if not url:
        raise ValueError("URL must not be empty")
    if not expected_sha256_hex:
        raise ValueError("Expected SHA-256 must be provided")
    norm_hash = ''.join(c for c in expected_sha256_hex.lower() if c in '0123456789abcdef')
    if len(norm_hash) != 64:
        raise ValueError("Expected SHA-256 must be 64 hex characters")

    req = urllib.request.Request(url, headers={"User-Agent": "Task86SecureDownloader/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        final_url = resp.geturl()
        parsed = urllib.parse.urlparse(final_url)
        if parsed.scheme.lower() != 'https':
            raise RuntimeError("Only HTTPS is allowed")
        host = parsed.hostname or ''
        host = host.lower()
        if host != 'drive.google.com' and not host.endswith('.googleusercontent.com'):
            raise RuntimeError(f"Disallowed host: {host}")

        # Content-Length check (may be absent)
        cl = resp.headers.get('Content-Length')
        if cl is not None:
            try:
                cl_val = int(cl)
                if cl_val > max_bytes:
                    raise RuntimeError(f"Content too large: {cl_val} > {max_bytes}")
            except ValueError:
                pass

        hasher = hashlib.sha256()
        fd, path = tempfile.mkstemp(prefix="task86_", suffix=".exe")
        os.close(fd)
        total = 0
        try:
            with open(path, 'wb') as f:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"Downloaded size exceeded limit: {total} > {max_bytes}")
                    hasher.update(chunk)
                    f.write(chunk)
        except Exception:
            try:
                os.remove(path)
            except OSError:
                pass
            raise

        actual_hex = hasher.hexdigest()
        if actual_hex.lower() != norm_hash:
            try:
                os.remove(path)
            except OSError:
                pass
            raise RuntimeError(f"SHA-256 mismatch. Expected {norm_hash} but got {actual_hex}")

        return os.path.abspath(path)

# Intentionally disabled: Executing arbitrary EXE is unsafe. Returns False and does not execute.
def execute_exe_securely(path: str) -> bool:
    # Disabled by design. If execution is ever enabled, implement:
    # - strict allowlist of trusted hashes and signer verification,
    # - explicit user consent,
    # - sandboxing and least privilege.
    return False

if __name__ == "__main__":
    tests = [
        ("https://drive.google.com/uc?export=download&id=FILE_ID_1", "0"*64),
        ("https://drive.google.com/uc?export=download&id=FILE_ID_2", "a"*64),
        ("http://drive.google.com/uc?export=download&id=FILE_ID_3", "b"*64),
        ("https://example.com/file.exe", "c"*64),
        ("https://drive.google.com/INVALID", "d"*64),
    ]
    for i, (u, h) in enumerate(tests, 1):
        print(f"Test {i}: URL={u}")
        try:
            p = download_exe_from_google_drive(u, h, 50*1024*1024)
            print(f"Downloaded to: {p}")
            print(f"Executed? {execute_exe_securely(p)}")
        except Exception as e:
            print(f"Failed: {e}")
        print("----")