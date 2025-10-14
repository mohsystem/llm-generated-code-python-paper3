#!/usr/bin/env python3
import http.server
import socketserver
import threading
import socket
import sys
from typing import Tuple, List, Any
import urllib.request
import urllib.error
import time
import xml.etree.ElementTree as ET

# Security: xml.etree does not process external entities/DTDs by default.

MAX_REQUEST_SIZE = 10 * 1024
HOST = "127.0.0.1"

def xml_escape(s: str) -> str:
    if s is None:
        return ""
    # Restrict to safe characters
    out = []
    for ch in s:
        if ch == "&":
            out.append("&amp;")
        elif ch == "<":
            out.append("&lt;")
        elif ch == ">":
            out.append("&gt;")
        elif ch == '"':
            out.append("&quot;")
        elif ch == "'":
            out.append("&apos;")
        else:
            code = ord(ch)
            if ch in ("\t", "\n", "\r") or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD:
                out.append(ch)
            else:
                out.append("?")
    return "".join(out)

def validate_string(s: str) -> str:
    if s is None:
        return ""
    if len(s) > 1000:
        raise ValueError("String too long")
    return s

def parse_value(value_elem: ET.Element) -> Any:
    # value may contain a single child type element or direct string
    children = [c for c in list(value_elem) if isinstance(c.tag, str)]
    if not children:
        # direct text
        return validate_string((value_elem.text or "").strip())
    type_elem = children[0]
    tag = type_elem.tag
    text = (type_elem.text or "").strip()
    if tag in ("int", "i4"):
        try:
            return int(text)
        except Exception:
            raise ValueError("Invalid integer")
    elif tag == "boolean":
        if text not in ("0", "1"):
            raise ValueError("Invalid boolean")
        return text == "1"
    elif tag == "string":
        return validate_string(text)
    else:
        raise ValueError(f"Unsupported XML-RPC type: {tag}")

def build_value_xml(obj: Any) -> str:
    if isinstance(obj, bool):
        return f"<value><boolean>{'1' if obj else '0'}</boolean></value>"
    if isinstance(obj, int):
        return f"<value><int>{obj}</int></value>"
    if isinstance(obj, str):
        return f"<value><string>{xml_escape(obj)}</string></value>"
    # Fallback to string representation
    return f"<value><string>{xml_escape(str(obj))}</string></value>"

def build_success_response(result: Any) -> bytes:
    xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
          "<methodResponse><params><param>" \
          f"{build_value_xml(result)}" \
          "</param></params></methodResponse>"
    return xml.encode("utf-8")

def build_fault_response(code: int, message: str) -> bytes:
    xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
          "<methodResponse><fault><value><struct>" \
          f"<member><name>faultCode</name><value><int>{code}</int></value></member>" \
          f"<member><name>faultString</name><value><string>{xml_escape(message)}</string></value></member>" \
          "</struct></value></fault></methodResponse>"
    return xml.encode("utf-8")

def parse_request_xml(data: bytes) -> Tuple[str, List[Any]]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise ValueError("Invalid XML")
    if root.tag != "methodCall":
        raise ValueError("Invalid XML-RPC: missing methodCall")
    method_name = None
    params: List[Any] = []
    for child in list(root):
        if child.tag == "methodName":
            method_name = (child.text or "").strip()
        elif child.tag == "params":
            for p in list(child):
                if p.tag != "param":
                    continue
                # find value
                value_elem = None
                for c in list(p):
                    if c.tag == "value":
                        value_elem = c
                        break
                if value_elem is None:
                    raise ValueError("Invalid XML-RPC: param missing value")
                params.append(parse_value(value_elem))
    if not method_name:
        raise ValueError("Invalid XML-RPC: missing methodName")
    return method_name, params

def dispatch(method: str, params: List[Any]) -> Any:
    if method == "add":
        if len(params) != 2 or not all(isinstance(x, int) for x in params):
            raise ValueError("Method add expects 2 ints")
        a, b = params
        s = a + b
        if s > 2**31 - 1 or s < -2**31:
            raise ValueError("Integer overflow")
        return s
    elif method == "concat":
        if len(params) != 2 or not all(isinstance(x, str) for x in params):
            raise ValueError("Method concat expects 2 strings")
        a = validate_string(params[0])
        b = validate_string(params[1])
        res = a + b
        if len(res) > 2000:
            raise ValueError("Resulting string too long")
        return res
    elif method == "factorial":
        if len(params) != 1 or not isinstance(params[0], int):
            raise ValueError("Method factorial expects 1 int")
        n = params[0]
        if n < 0 or n > 12:
            raise ValueError("n must be 0..12")
        f = 1
        for i in range(2, n + 1):
            f *= i
        return f
    elif method == "reverse":
        if len(params) != 1 or not isinstance(params[0], str):
            raise ValueError("Method reverse expects 1 string")
        s = validate_string(params[0])
        return s[::-1]
    elif method == "isEven":
        if len(params) != 1 or not isinstance(params[0], int):
            raise ValueError("Method isEven expects 1 int")
        return (params[0] % 2) == 0
    else:
        raise ValueError("Unknown method: " + method)

class XmlRpcRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureXMLRPC/1.0"

    def do_POST(self) -> None:
        try:
            # Restrict to localhost only
            host, _ = self.client_address
            if host not in ("127.0.0.1", "::1"):
                self._send_response(403, b"text/plain; charset=utf-8", b"Forbidden")
                return
            cl_header = self.headers.get('Content-Length')
            if cl_header is None:
                self._send_response(411, b"text/plain; charset=utf-8", b"Length Required")
                return
            try:
                content_length = int(cl_header.strip())
            except Exception:
                self._send_response(400, b"text/plain; charset=utf-8", b"Bad Content-Length")
                return
            if content_length < 0 or content_length > MAX_REQUEST_SIZE:
                self._send_response(413, b"text/plain; charset=utf-8", b"Payload Too Large")
                return
            data = self.rfile.read(content_length)
            method, params = parse_request_xml(data)
            result = dispatch(method, params)
            resp = build_success_response(result)
            self._send_response(200, b"text/xml; charset=utf-8", resp)
        except ValueError as ve:
            resp = build_fault_response(1, str(ve))
            self._send_response(200, b"text/xml; charset=utf-8", resp)
        except Exception:
            resp = build_fault_response(2, "Server error")
            self._send_response(200, b"text/xml; charset=utf-8", resp)

    def log_message(self, format: str, *args) -> None:
        # Suppress default logging to keep output clean
        pass

    def _send_response(self, status: int, content_type: bytes, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type.decode("ascii"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False

def start_server(port: int) -> Tuple[ThreadedHTTPServer, threading.Thread, int]:
    server = ThreadedHTTPServer((HOST, port), XmlRpcRequestHandler)
    actual_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, name="XMLRPCServer")
    t.daemon = True
    t.start()
    return server, t, actual_port

def stop_server(server: ThreadedHTTPServer) -> None:
    server.shutdown()
    server.server_close()

def build_request_xml(method: str, params: List[Any]) -> bytes:
    sb = []
    sb.append('<?xml version="1.0" encoding="UTF-8"?>')
    sb.append("<methodCall>")
    sb.append("<methodName>" + xml_escape(method) + "</methodName>")
    sb.append("<params>")
    for p in params:
        sb.append("<param>")
        sb.append(build_value_xml(p))
        sb.append("</param>")
    sb.append("</params></methodCall>")
    return "".join(sb).encode("utf-8")

def parse_response_xml(data: bytes) -> Any:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise ValueError("Invalid XML")
    if root.tag != "methodResponse":
        raise ValueError("Invalid response")
    fault = root.find("fault")
    if fault is not None:
        raise ValueError("Fault")
    params = root.find("params")
    if params is None:
        raise ValueError("Missing params")
    param = params.find("param")
    if param is None:
        raise ValueError("Missing param")
    value = param.find("value")
    if value is None:
        raise ValueError("Missing value")
    return parse_value(value)

def call_xmlrpc(port: int, method: str, params: List[Any]) -> Any:
    data = build_request_xml(method, params)
    req = urllib.request.Request(f"http://{HOST}:{port}/", data=data, headers={"Content-Type": "text/xml; charset=utf-8"}, method="POST")
    with urllib.request.urlopen(req, timeout=3) as resp:
        resp_data = resp.read()
    return parse_response_xml(resp_data)

def main() -> int:
    # Choose an available port securely
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        port = s.getsockname()[1]
    server, thread, actual_port = start_server(port)
    try:
        r1 = call_xmlrpc(actual_port, "add", [5, 7])
        print(f"add(5,7) = {r1}")
        r2 = call_xmlrpc(actual_port, "concat", ["Hello, ", "World"])
        print(f"concat = {r2}")
        r3 = call_xmlrpc(actual_port, "factorial", [5])
        print(f"factorial(5) = {r3}")
        r4 = call_xmlrpc(actual_port, "reverse", ["abcd"])
        print(f"reverse = {r4}")
        r5 = call_xmlrpc(actual_port, "isEven", [8])
        print(f"isEven(8) = {r5}")
        return 0
    finally:
        stop_server(server)
        thread.join(timeout=2)

if __name__ == "__main__":
    sys.exit(main())