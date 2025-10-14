
import base64
import json

def process_request(raw_data):
    try:
        # Step 1 & 2: Ensure UTF-8 encoding and decode Base64
        decoded_bytes = base64.b64decode(raw_data.encode('utf-8'))
        
        # Step 3: Deserialize the decoded data (assuming JSON format)
        decoded_string = decoded_bytes.decode('utf-8')
        deserialized_data = json.loads(decoded_string)
        
        # Step 4 & 5: Store and return the deserialized data
        return deserialized_data
        
    except Exception as e:
        print(f"Error processing request: {e}")
        return None

if __name__ == "__main__":
    # Test Case 1: Simple JSON object
    test1 = base64.b64encode('{"name":"John","age":30}'.encode('utf-8')).decode('utf-8')
    print("Test 1:", process_request(test1))
    
    # Test Case 2: JSON array
    test2 = base64.b64encode('[1,2,3,4,5]'.encode('utf-8')).decode('utf-8')
    print("Test 2:", process_request(test2))
    
    # Test Case 3: Nested JSON
    test3 = base64.b64encode('{"user":{"id":1,"name":"Alice"}}'.encode('utf-8')).decode('utf-8')
    print("Test 3:", process_request(test3))
    
    # Test Case 4: JSON with special characters
    test4 = base64.b64encode('{"message":"Hello, World!"}'.encode('utf-8')).decode('utf-8')
    print("Test 4:", process_request(test4))
    
    # Test Case 5: Empty JSON object
    test5 = base64.b64encode('{}'.encode('utf-8')).decode('utf-8')
    print("Test 5:", process_request(test5))
