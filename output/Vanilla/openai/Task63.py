import base64
import json
import xml.etree.ElementTree as ET

def process_request(raw_data):
    if isinstance(raw_data, bytes):
        base64_str = raw_data.decode('utf-8')
    else:
        base64_str = str(raw_data)
    decoded_bytes = base64.b64decode(base64_str)
    decoded_str = decoded_bytes.decode('utf-8').strip()
    # Try JSON
    try:
        data = json.loads(decoded_str)
        stored = data
        return stored
    except Exception:
        pass
    # Try XML
    try:
        elem = ET.fromstring(decoded_str)
        stored = elem
        return stored
    except Exception:
        pass
    # Fallback to string
    stored = decoded_str
    return stored

if __name__ == "__main__":
    samples = [
        '{"name":"Alice","age":30,"skills":["Java","Python"],"active":true}',
        '<user><name>Bob</name><age>25</age></user>',
        '[1,2,3,"x"]',
        'Hello, world!',
        '{"a":{"b":[1,{"c":"d"}]},"n":null}'
    ]
    for i, s in enumerate(samples, 1):
        b64 = base64.b64encode(s.encode('utf-8'))
        out = process_request(b64)
        if isinstance(out, ET.Element):
            print(f"Test {i}: XML tag={out.tag}, children={[child.tag for child in out]}")
        else:
            print(f"Test {i}: {out}")