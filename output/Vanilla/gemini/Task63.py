import base64
import json

# In Python, there is no strict requirement for a class name like 'Task63' for a script.
# The functionality is organized into functions.

def process_request(raw_data: str) -> dict:
    """
    Processes a raw request by Base64 decoding and deserializing the data.

    :param raw_data: The Base64 encoded, UTF-8 string data.
    :return: The deserialized data as a Python dictionary.
    """
    # Step 1: Retrieve the raw_data. (Passed as parameter)
    # The input raw_data is a string, which is what b64decode expects.
    # It's assumed the data was originally UTF-8 encoded before Base64.
    
    # Step 2: Decode the raw_data using Base64.
    decoded_bytes = base64.b64decode(raw_data)

    # Step 3: Deserialize the decoded data.
    # First, decode the bytes from UTF-8 into a string.
    json_string = decoded_bytes.decode('utf-8')
    # Then, parse the JSON string into a Python object (dictionary).
    deserialized_data = json.loads(json_string)

    # Step 4 & 5: Store the deserialized data in a variable and return it.
    return deserialized_data

def main():
    """Main function to run test cases."""
    test_cases = [
        "eyJpZCI6IDEyMywgIm5hbWUiOiAidGVzdF91c2VyIiwgImFjdGl2ZSI6IHRydWV9",
        "eyJtZXNzYWdlIjogIkhlbGxvLCBXb3JsZCEifQ==",
        "eyJkYXRhIjogWzEsIDIsIDNdLCAic3RhdHVzIjogIm9rIn0=",
        "eyJlcnJvciI6ICJOb3QgRm91bmQiLCAiY29kZSI6IDQwNH0=",
        "e30="
    ]

    print("--- Python Test Cases ---")
    for i, raw_data in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input (Base64): {raw_data}")
        result = process_request(raw_data)
        print(f"Output (Deserialized): {result}")
        print()

if __name__ == "__main__":
    main()