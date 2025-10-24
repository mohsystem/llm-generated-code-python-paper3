import sys
import json
import ssl
import io
import threading
import socket
from typing import Any, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def fetch_json_from_url(url: str, timeout: float = 10.0, max_bytes: int = 5 * 1024 * 1024) -> Any:
    """
    Fetch a JSON document from the given HTTP/HTTPS URL, parse it, and return the JSON object.

    Parameters:
        url (str): The URL to fetch.
        timeout (float): Timeout in seconds for the network operation.
        max_bytes (int): Maximum number of bytes to read from the response.

    Returns:
        Any: The parsed JSON object (dict, list, etc.).

    Raises:
        ValueError: If the URL is invalid, response too large, non-2xx status, or JSON is invalid.
        OSError: For network errors such as timeouts or connection failures.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    url = url.strip()
    if not url:
        raise ValueError("URL must not be empty")
    if len(url) > 2048:
        raise ValueError("URL is too long")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL scheme must be http or https")
    if not parsed.netloc:
        raise ValueError("URL must include a network location (host)")

    headers = {
        "User-Agent": "SecureJsonFetcher/1.0",
        "Accept": "application/json, */*;q=0.8",
    }
    req = Request(url, headers=headers, method="GET")

    context: Optional[ssl.SSLContext] = None
    if parsed.scheme == "https":
        # Create a secure default SSL context with hostname verification and cert validation.
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

    try:
        # Open the URL with a timeout and secure context for HTTPS.
        with urlopen(req, timeout=timeout, context=context) as resp:
            status = getattr(resp, "status", None)
            if status is None:
                # Fallback for very old Python versions; assume OK if not provided.
                status = 200
            if not (200 <= status < 300):
                raise ValueError(f"HTTP error: status {status}")

            # Enforce size limits using Content-Length if present.
            cl_hdr = resp.headers.get("Content-Length")
            if cl_hdr is not None:
                try:
                    content_length = int(cl_hdr)
                    if content_length < 0:
                        raise ValueError("Invalid Content-Length")
                    if content_length > max_bytes:
                        raise ValueError(f"Response too large (Content-Length {content_length} > {max_bytes})")
                except ValueError:
                    # If Content-Length is invalid, fall back to streaming checks.
                    pass

            # Stream the body with a maximum size cap.
            buf = io.BytesIO()
            chunk_size = 8192
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                buf.write(chunk)
                if buf.tell() > max_bytes:
                    raise ValueError(f"Response exceeds maximum allowed size of {max_bytes} bytes")

            data_bytes = buf.getvalue()

    except ssl.SSLError as e:
        raise OSError(f"SSL error: {e}") from e
    except OSError as e:
        # Includes timeout, DNS failure, connection errors, etc.
        raise OSError(f"Network error: {e}") from e

    # Decode and parse JSON. JSON text MUST be UTF-8 per RFC 8259; handle UTF-8 BOM if present.
    try:
        text = data_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise ValueError(f"Failed to decode response as UTF-8 JSON: {e}") from e

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e.msg} at line {e.lineno} column {e.colno}") from e


# ---- Test Server and Test Runner ----

class _TestJSONHandler(BaseHTTPRequestHandler):
    # Sizes configured by the launcher
    small_json_size: int = 1024  # default fallback
    large_json_size: int = 1024 * 100  # default fallback

    def log_message(self, format: str, *args) -> None:
        # Silence server logs for cleaner test output
        pass

    def do_GET(self) -> None:
        try:
            if self.path == "/valid":
                body = json.dumps({"message": "hello", "value": 123}, separators=(",", ":")).encode("utf-8")
                self._send_json(200, body)
            elif self.path == "/array":
                body = json.dumps([1, 2, 3, {"a": True}], separators=(",", ":")).encode("utf-8")
                self._send_json(200, body)
            elif self.path == "/invalid":
                body = b"not json"
                self._send_bytes(200, "text/plain; charset=utf-8", body)
            elif self.path == "/large":
                # Create a JSON object with a string close to large_json_size
                payload_size = max(0, self.large_json_size - 100)
                big_str = "a" * payload_size
                body = json.dumps({"data": big_str}, separators=(",", ":")).encode("utf-8")
                self._send_json(200, body)
            elif self.path == "/toolarge":
                payload_size = self.large_json_size + 200
                big_str = "b" * payload_size
                body = json.dumps({"data": big_str}, separators=(",", ":")).encode("utf-8")
                self._send_json(200, body)
            else:
                self._send_json(404, json.dumps({"error": "not found"}).encode("utf-8"))
        except Exception:
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "internal"}).encode("utf-8"))
            except Exception:
                pass

    def _send_json(self, status_code: int, body: bytes) -> None:
        self._send_bytes(status_code, "application/json; charset=utf-8", body)

    def _send_bytes(self, status_code: int, content_type: str, body: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_test_server(small_json_size: int, large_json_size: int) -> Tuple[ThreadingHTTPServer, threading.Thread, str]:
    # Bind to an ephemeral port on localhost
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TestJSONHandler)
    _TestJSONHandler.small_json_size = small_json_size
    _TestJSONHandler.large_json_size = large_json_size

    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    t = threading.Thread(target=server.serve_forever, name="TestHTTPServer", daemon=True)
    t.start()
    return server, t, base_url


def _run_tests() -> None:
    print("Running 5 test cases...")

    # Use a smaller cap for tests to exercise the size checks deterministically.
    max_bytes_test = 50 * 1024  # 50 KiB
    server, thread, base_url = _start_test_server(1024, max_bytes_test)

    def run_case(name: str, url: str, expect_error: bool = False, override_max_bytes: Optional[int] = None) -> None:
        print(f"\nTEST: {name}")
        try:
            result = fetch_json_from_url(url, timeout=5.0, max_bytes=(override_max_bytes or max_bytes_test))
            print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
            if expect_error:
                print("Expected error but succeeded")
        except Exception as e:
            print(f"ERROR: {e}")
            if not expect_error:
                print("Unexpected error")

    try:
        # 1) Valid JSON object
        run_case("Valid JSON object", f"{base_url}/valid")

        # 2) Valid JSON array
        run_case("Valid JSON array", f"{base_url}/array")

        # 3) Invalid JSON content
        run_case("Invalid JSON content", f"{base_url}/invalid", expect_error=True)

        # 4) Response exceeds size limit
        run_case("Too large JSON payload", f"{base_url}/toolarge", expect_error=True)

        # 5) Malformed URL
        run_case("Malformed URL", "ht!tp://bad host", expect_error=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)
        print("\nTest server shut down.")


def _print_usage() -> None:
    print("Usage:")
    print(f"  {sys.argv[0]} <http-or-https-URL>")
    print("If no URL is provided, built-in tests are executed.")


def main() -> None:
    if len(sys.argv) == 2:
        url = sys.argv[1]
        try:
            obj = fetch_json_from_url(url)
            print(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)
    elif len(sys.argv) == 1:
        _run_tests()
    else:
        _print_usage()
        sys.exit(2)


if __name__ == "__main__":
    main()