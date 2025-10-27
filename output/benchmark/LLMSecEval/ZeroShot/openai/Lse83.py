import json

MAX_BODY_SIZE = 10 * 1024  # 10KB

def handle_request(content_type: str, body: bytes) -> str:
    if not isinstance(content_type, str) or not isinstance(body, (bytes, bytearray)):
        return ""
    ct = content_type.strip().lower()
    if not ct.startswith("application/json"):
        return ""
    if len(body) == 0 or len(body) > MAX_BODY_SIZE:
        return ""
    try:
        text = body.decode("utf-8", errors="strict")
    except Exception:
        return ""
    try:
        data = json.loads(text)
    except Exception:
        return ""
    if isinstance(data, dict):
        val = data.get("name")
        if isinstance(val, str):
            return val
    # Optionally search nested dicts for 'name'
    def _find_name(obj):
        if isinstance(obj, dict):
            if "name" in obj and isinstance(obj["name"], str):
                return obj["name"]
            for v in obj.values():
                found = _find_name(v)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for v in obj:
                found = _find_name(v)
                if found is not None:
                    return found
        return None
    found = _find_name(data)
    return found if isinstance(found, str) else ""

if __name__ == "__main__":
    tests = [
        ('application/json', b'{"name":"Alice"}'),
        ('application/json', b'{"id":1,"name":"Bob \\\\ \\"The Builder\\""}'),
        ('application/json', b'{"id":7,"names":["x","y"]}'),
        ('application/json', b'{malformed json'),
        ('application/json', b'{"nested":{"name":"Carol"},"other":1}')
    ]
    for i, (ct, body) in enumerate(tests, 1):
        print(f"Test {i} => {handle_request(ct, body)}")