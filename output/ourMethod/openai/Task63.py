import base64
from typing import Optional

def _is_ascii(s: str) -> bool:
    try:
        s.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False

def _strip_ws(s: str) -> str:
    return ''.join(c for c in s if c not in (' ', '\n', '\r', '\t'))

def _is_base64_chars(s: str) -> bool:
    for c in s:
        if not (('A' <= c <= 'Z') or ('a' <= c <= 'z') or ('0' <= c <= '9') or c in '+/='
                ):
            return False
    return True

def _contains_disallowed_ctrl(s: str) -> bool:
    for ch in s:
        code = ord(ch)
        if 0x00 <= code <= 0x1F and code not in (0x09, 0x0A, 0x0D):
            return True
    return False

def process_request(raw_data_b64: str, data_type: str) -> str:
    if raw_data_b64 is None or data_type is None:
        return "ERROR: Null input"

    dtype = data_type.strip().lower()
    if dtype not in ("json", "xml"):
        return "ERROR: Unsupported data type"

    if not _is_ascii(raw_data_b64):
        return "ERROR: raw_data must be ASCII/Base64 characters"

    sanitized = _strip_ws(raw_data_b64)

    if not _is_base64_chars(sanitized):
        return "ERROR: Invalid Base64 characters"

    max_decoded = 1024 * 1024  # 1 MiB
    max_b64_len = ((max_decoded + 2) // 3) * 4
    if len(sanitized) > max_b64_len:
        return "ERROR: Input too large"

    try:
        decoded_bytes = base64.b64decode(sanitized, validate=True)
    except Exception:
        return "ERROR: Base64 decoding failed"

    if len(decoded_bytes) > max_decoded:
        return "ERROR: Decoded data too large"

    try:
        decoded_text = decoded_bytes.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        return "ERROR: Decoded bytes are not valid UTF-8"

    content = decoded_text.strip()

    if dtype == "json":
        if not (content.startswith("{") or content.startswith("[")):
            return "ERROR: JSON must start with '{' or '['"
        if _contains_disallowed_ctrl(content):
            return "ERROR: JSON contains disallowed control characters"
        return decoded_text
    else:
        if not content.startswith("<"):
            return "ERROR: XML must start with '<'"
        lower = content.lower()
        if "<!doctype" in lower or "<!entity" in lower:
            return "ERROR: XML contains disallowed DOCTYPE or ENTITY"
        # Attempt safe parse to validate well-formedness; stdlib doesn't resolve external entities
        try:
            import xml.etree.ElementTree as ET
            ET.fromstring(content)
        except Exception:
            return "ERROR: XML parsing/validation failed"
        return decoded_text

def _to_b64(s: str) -> str:
    return base64.b64encode(s.encode('utf-8')).decode('ascii')

if __name__ == "__main__":
    json1 = '{"msg":"hello","n":5}'
    json2 = '["hello",2,true]'
    xml1  = '<root><a>1</a><b>x</b></root>'
    invalid_b64 = '!!!not_base64!!!'
    xml_doctype = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

    b64json1 = _to_b64(json1)
    b64json2 = _to_b64(json2)
    b64xml1  = _to_b64(xml1)
    b64xml_doctype = _to_b64(xml_doctype)

    print(process_request(b64json1, "json"))
    print(process_request(b64json2, "json"))
    print(process_request(b64xml1,  "xml"))
    print(process_request(invalid_b64, "json"))
    print(process_request(b64xml_doctype, "xml"))