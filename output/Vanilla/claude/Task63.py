
import base64
import json

def process_request(raw_data):
    try:
        # Step 1: Ensure raw_data is encoded in UTF-8
        raw_data_bytes = raw_data.encode('utf-8')
        
        # Step 2: Decode the raw_data using Base64
        decoded_bytes = base64.b64decode(raw_data_bytes)
        
        # Step 3: Convert decoded bytes to string
        decoded_data = decoded_bytes.decode('utf-8')
        
        # Step 4: Deserialize the decoded data (assuming JSON format)
        stored_data = json.loads(decoded_data)
        
        # Step 5: Return the stored data
        return json.dumps(stored_data)
    except Exception as e:
        return f"Error processing request: {str(e)}"

if __name__ == "__main__":
    # Test case 1: Simple JSON object
    test1 = base64.b64encode('{"name":"John","age":30}'.encode('utf-8')).decode('utf-8')
    print("Test 1:", process_request(test1))
    
    # Test case 2: JSON with nested object
    test2 = base64.b64encode('{"user":{"id":1,"name":"Alice"}}'.encode('utf-8')).decode('utf-8')
    print("Test 2:", process_request(test2))
    
    # Test case 3: JSON with array
    test3 = base64.b64encode('{"items":[1,2,3,4,5]}'.encode('utf-8')).decode('utf-8')
    print("Test 3:", process_request(test3))
    
    # Test case 4: JSON with boolean and null
    test4 = base64.b64encode('{"active":true,"data":null}'.encode('utf-8')).decode('utf-8')
    print("Test 4:", process_request(test4))
    
    # Test case 5: Complex JSON
    test5 = base64.b64encode('{"company":"TechCorp","employees":[{"name":"Bob","role":"Developer"}]}'.encode('utf-8')).decode('utf-8')
    print("Test 5:", process_request(test5))
