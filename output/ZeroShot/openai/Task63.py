import base64

MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10MB

def process_request(raw_data: bytes) -> str:
    if raw_data is None:
        raise ValueError("raw_data is None")
    if len(raw_data) > MAX_INPUT_BYTES:
        raise ValueError("Input too large")

    # Ensure raw_data is UTF-8 (base64 text)
    b64_text = raw_data.decode('utf-8', 'strict')

    # Strict Base64 decode
    decoded_bytes = base64.b64decode(b64_text, validate=True)

    # Decode payload as UTF-8 text (JSON/XML/plain text)
    deserialized = decoded_bytes.decode('utf-8', 'strict')
    stored_data = deserialized
    return stored_data

def _b64_encode_utf8(s: str) -> str:
    return base64.b64encode(s.encode('utf-8')).decode('ascii')

if __name__ == "__main__":
    originals = [
        '{"name":"Alice","age":30}',
        '<person><name>Alice</name><age>30</age></person>',
        '["x",1,true,null]',
        '<root/>',
        'Hello, 世界',
    ]
    for i, original in enumerate(originals, start=1):
        try:
            b64 = _b64_encode_utf8(original)
            result = process_request(b64.encode('utf-8'))
            print(f"Test {i} OK: {result}")
        except Exception as e:
            print(f"Test {i} Error: {e}")