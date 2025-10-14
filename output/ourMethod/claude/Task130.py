from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Set
import json
import re

ALLOWED_ORIGINS: Set[str] = {
    "https://example.com",
    "https://app.example.com"
}

ALLOWED_METHODS: Set[str] = {"GET", "POST", "OPTIONS"}
ALLOWED_HEADERS: Set[str] = {"Content-Type", "Authorization"}
MAX_AGE: int = 3600


class CORSHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self) -> None:
        self._handle_cors()
        self._handle_preflight()

    def do_GET(self) -> None:
        self._handle_cors()
        if self._is_method_allowed("GET"):
            self._handle_actual_request("GET")
        else:
            self._send_error_response(405, "Method Not Allowed")

    def do_POST(self) -> None:
        self._handle_cors()
        if self._is_method_allowed("POST"):
            self._handle_actual_request("POST")
        else:
            self._send_error_response(405, "Method Not Allowed")

    def _handle_cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin and len(origin) <= 256:
            origin = self._sanitize_header(origin)
            if origin in ALLOWED_ORIGINS:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")

    def _handle_preflight(self) -> None:
        request_method = self.headers.get("Access-Control-Request-Method", "")
        request_headers = self.headers.get("Access-Control-Request-Headers", "")

        if request_method and len(request_method) <= 20:
            request_method = self._sanitize_header(request_method)
            if request_method in ALLOWED_METHODS:
                self.send_response(204)
                self._handle_cors()
                self.send_header("Access-Control-Allow-Methods", ", ".join(ALLOWED_METHODS))

                if request_headers and len(request_headers) <= 256:
                    request_headers = self._sanitize_header(request_headers)
                    headers_list = [h.strip() for h in request_headers.split(",")]
                    if all(h in ALLOWED_HEADERS for h in headers_list):
                        self.send_header("Access-Control-Allow-Headers", ", ".join(ALLOWED_HEADERS))

                self.send_header("Access-Control-Max-Age", str(MAX_AGE))
                self.end_headers()
            else:
                self._send_error_response(405, "Method Not Allowed")
        else:
            self._send_error_response(400, "Bad Request")

    def _handle_actual_request(self, method: str) -> None:
        response_data = {"status": "success", "method": self._escape_json(method)}
        response_json = json.dumps(response_data)
        response_bytes = response_json.encode("utf-8")

        self.send_response(200)
        self._handle_cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_error_response(self, code: int, message: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(message.encode("utf-8"))

    def _is_method_allowed(self, method: str) -> bool:
        return method in ALLOWED_METHODS

    def _sanitize_header(self, header: str) -> str:
        if not header:
            return ""
        return re.sub(r'[^a-zA-Z0-9:/.\\\-_,\s]', '', header)

    def _escape_json(self, input_str: str) -> str:
        if not input_str:
            return ""
        return (
            input_str
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )

    def log_message(self, format: str, *args) -> None:
        pass


def main() -> None:
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, CORSHandler)

    print("Test Case 1: Server started on port 8080")
    print(f"Test Case 2: Allowed origins: {ALLOWED_ORIGINS}")
    print(f"Test Case 3: Allowed methods: {ALLOWED_METHODS}")
    print(f"Test Case 4: Allowed headers: {ALLOWED_HEADERS}")
    print(f"Test Case 5: Max age: {MAX_AGE} seconds")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
        print("\nServer stopped")


if __name__ == "__main__":
    main()
