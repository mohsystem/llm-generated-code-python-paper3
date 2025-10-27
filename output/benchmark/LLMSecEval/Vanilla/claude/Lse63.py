
def process_file(input_file_path, output_file_path):
    try:
        # Read file contents into buffer
        with open(input_file_path, 'rb') as f:
            buffer = f.read()
        
        bytes_read = len(buffer)
        
        # Calculate checksum
        checksum = sum(buffer)
        
        # Write results to output file
        with open(output_file_path, 'w') as f:
            f.write(f"Bytes Read: {bytes_read}\\n")
            f.write(f"Checksum: {checksum}\\n")
        
        return bytes_read, checksum
    except Exception as e:
        print(f"Error: {e}")
        return 0, 0

if __name__ == "__main__":
    # Test case 1: Empty file
    with open("test1.txt", 'wb') as f:
        f.write(b'')
    r1 = process_file("test1.txt", "output1.txt")
    print(f"Test 1 - Bytes: {r1[0]}, Checksum: {r1[1]}")
    
    # Test case 2: Small text file
    with open("test2.txt", 'wb') as f:
        f.write(b'Hello')
    r2 = process_file("test2.txt", "output2.txt")
    print(f"Test 2 - Bytes: {r2[0]}, Checksum: {r2[1]}")
    
    # Test case 3: Numbers
    with open("test3.txt", 'wb') as f:
        f.write(b'12345')
    r3 = process_file("test3.txt", "output3.txt")
    print(f"Test 3 - Bytes: {r3[0]}, Checksum: {r3[1]}")
    
    # Test case 4: Special characters
    with open("test4.txt", 'wb') as f:
        f.write(b'!@#$%')
    r4 = process_file("test4.txt", "output4.txt")
    print(f"Test 4 - Bytes: {r4[0]}, Checksum: {r4[1]}")
    
    # Test case 5: Binary data
    with open("test5.txt", 'wb') as f:
        f.write(bytes([1, 2, 3, 4, 5, 255, 254, 253]))
    r5 = process_file("test5.txt", "output5.txt")
    print(f"Test 5 - Bytes: {r5[0]}, Checksum: {r5[1]}")
