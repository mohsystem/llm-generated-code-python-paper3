import json
from typing import Optional, Union
from urllib.parse import parse_qs, unquote_plus

MAX_PAYLOAD_BYTES = 8192
MAX_NAME_CHARS = 256

def _is_valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if not (1 <= len(name) <= MAX_NAME_CHARS):
        return False
    if any(ord(ch) < 0x20 for ch in name):
        return False
    return True

def _json_error(msg: str) -> str:
    return json.dumps({"error": msg}, ensure_ascii=True)

def _extract_from_json(body: str) -> Optional[str]:
    try:
        obj = json.loads(body)
    except Exception:
        return None
    # Support nested - look for top-level first, else search recursively for first string 'name'
    if isinstance(obj, dict) and isinstance(obj.get("name"), str):
        return obj["name"]
    # Recursive search
    def walk(v) -> Optional[str]:
        if isinstance(v, dict):
            if isinstance(v.get("name"), str):
                return v["name"]
            for vv in v.values():
                r = walk(vv)
                if r is not None:
                    return r
        elif isinstance(v, list):
            for it in v:
                r = walk(it)
                if r is not None:
                    return r
        return None
    return walk(obj)

def _extract_from_form(body: str) -> Optional[str]:
    try:
        # parse_qs handles percent-decoding, but keep a size guard
        if len(body) > MAX_PAYLOAD_BYTES:
            return None
        qs = parse_qs(body, strict_parsing=False, keep_blank_values=True, encoding="utf-8", errors="strict")
        vals = qs.get("name")
        if not vals:
            return None
        # choose first value
        return vals[0]
    except Exception:
        return None

def process_payload(payload: Union[bytes, str], content_type: Optional[str]) -> str:
    if payload is None:
        return _json_error("invalid input")
    if isinstance(payload, str):
        body_bytes = payload.encode("utf-8", "strict")
    else:
        body_bytes = payload
    if len(body_bytes) > MAX_PAYLOAD_BYTES:
        return _json_error("payload too large")
    try:
        body = body_bytes.decode("utf-8", "strict")
    except Exception:
        return _json_error("invalid encoding")

    ct = (content_type or "").lower()
    name = None

    if "application/json" in ct or (ct == "" and body.lstrip().startswith("{")):
        name = _extract_from_json(body)
    elif "application/x-www-form-urlencoded" in ct or (ct == "" and "=" in body):
        name = _extract_from_form(body)
    else:
        # Try both if unknown
        name = _extract_from_json(body)
        if name is None:
            name = _extract_from_form(body)

    if name is None:
        return _json_error("name field missing")
    if not _is_valid_name(name):
        return _json_error("invalid name")
    return json.dumps({"name": name}, ensure_ascii=True)

if __name__ == "__main__":
    tests = [
        (b'{"name":"Alice"}', "application/json"),
        (b'{"age":30}', "application/json"),
        (b"name=Bob%20Builder&role=dev", "application/x-www-form-urlencoded"),
        (('{"name":"' + ("x" * 300) + '"}').encode("utf-8"), "application/json"),
        (b"invalid_payload", None),
    ]
    for idx, (p, ct) in enumerate(tests, 1):
        print(f"Test {idx}: {process_payload(p, ct)}")