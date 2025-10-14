# Chain-of-Through process in code generation:
# 1) Problem understanding: Validate request bytes are UTF-8 for Base64 text; Base64-decode; parse JSON/XML; return structure.
# 2) Security requirements: strict UTF-8, strict Base64, size limits, safe XML parsing (ElementTree has no external entities), robust error handling.
# 3) Secure coding generation: enforce limits and strict decoding, try JSON then XML, return original string if neither.
# 4) Code review: ensured no external entity resolution, added limits and validation.
# 5) Secure code output: final function below.

import base64
import json
import sys
from typing import Any, Dict, List, Union
import xml.etree.ElementTree as ET

MAX_RAW_BYTES = 1_000_000
MAX_DECODED_BYTES = 1_000_000
MAX_PRINT_LEN = 10_000  # for safe printing in tests

def process_request(raw_data: bytes) -> Any:
    if raw_data is None:
        raise ValueError("raw_data is None")
    if not isinstance(raw_data, (bytes, bytearray)):
        raise TypeError("raw_data must be bytes")
    if len(raw_data) == 0:
        raise ValueError("raw_data is empty")
    if len(raw_data) > MAX_RAW_BYTES:
        raise ValueError("raw_data exceeds maximum allowed size")

    # Ensure UTF-8
    try:
        base64_text = raw_data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("raw_data is not valid UTF-8") from e
    base64_text = base64_text.strip()
    if not base64_text:
        raise ValueError("Base64 text is empty after trimming")

    # Strict Base64
    try:
        decoded = base64.b64decode(base64_text, validate=True)
    except Exception as e:
        raise ValueError("Invalid Base64 input") from e

    if len(decoded) > MAX_DECODED_BYTES:
        raise ValueError("Decoded data exceeds maximum allowed size")

    # Payload text (JSON/XML expected to be text)
    try:
        payload = decoded.decode("utf-8").strip()
    except UnicodeDecodeError as e:
        raise ValueError("Decoded payload is not valid UTF-8") from e
    if not payload:
        raise ValueError("Decoded payload is empty")

    t = payload.lstrip()
    # Try JSON
    if t.startswith("{") or t.startswith("["):
        try:
            return json.loads(payload)
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON payload") from e
    # Try XML
    if t.startswith("<"):
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as e:
            raise ValueError("Invalid XML payload") from e
        return _xml_to_dict(root)
    # Fallback: return as plain text
    return payload

def _xml_to_dict(elem: ET.Element) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "tag": elem.tag,
        "attributes": dict(elem.attrib),
        "text": (elem.text or "").strip(),
        "children": []
    }
    for child in list(elem):
        d["children"].append(_xml_to_dict(child))
    return d

def _pretty(obj: Any) -> str:
    try:
        if isinstance(obj, (dict, list)):
            return json.dumps(obj, ensure_ascii=False)
        if isinstance(obj, str):
            return json.dumps(obj, ensure_ascii=False)
        return str(obj)
    except Exception:
        s = str(obj)
        if len(s) > MAX_PRINT_LEN:
            s = s[:MAX_PRINT_LEN] + "...(truncated)"
        return s

if __name__ == "__main__":
    def mk_input(payload: str) -> bytes:
        return base64.b64encode(payload.encode("utf-8"))

    # 5 test cases
    tests = [
        mk_input('{"name":"Alice","age":30,"active":true}'),
        mk_input('[{"id":1},{"id":2},{"id":3}]'),
        mk_input('<root attr="v"><child>text</child><child2 x="1"/></root>'),
        b"!!not-base64!!",
        bytes([0xC3, 0x28])  # invalid UTF-8
    ]
    for idx, t in enumerate(tests, 1):
        print(f"Test {idx}:")
        try:
            out = process_request(t)
            print(_pretty(out))
        except Exception as e:
            print("Error:", str(e))
        print()