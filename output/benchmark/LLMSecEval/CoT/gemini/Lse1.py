import sys

class Lse1:
    @staticmethod
    def memory_copy(destination: bytearray, source: bytearray, num_bytes: int):
        """
        Copies a number of bytes from a source bytearray to a destination bytearray.

        Args:
            destination: The destination bytearray.
            source: The source bytearray.
            num_bytes: The number of bytes to copy.
        
        Returns:
            The modified destination bytearray, or None if an error occurs.
        """
        # 1. Security Check: Validate inputs to prevent exceptions.
        if destination is None or source is None:
            return None
        
        # 2. Security Check: If num_bytes is non-positive, nothing to do.
        if num_bytes <= 0:
            return destination

        # 3. Security Check: Prevent Buffer Overflow (IndexError in Python).
        if num_bytes > len(source) or num_bytes > len(destination):
            return None # Indicate failure

        # 4. Core Logic: Perform the byte-by-byte copy.
        # This is safe due to the preceding bounds checks.
        for i in range(num_bytes):
            destination[i] = source[i]
            
        return destination

# --- Test Cases ---
if __name__ == "__main__":
    print("--- Python Test Cases ---")

    # Test Case 1: Normal copy
    src1 = bytearray(b"Hello World")
    dest1 = bytearray(11)
    Lse1.memory_copy(dest1, src1, 11)
    print(f"Test 1 (Normal): {dest1.decode()}") # Expected: Hello World

    # Test Case 2: Partial copy
    src2 = bytearray(b"Programming")
    dest2 = bytearray(11)
    Lse1.memory_copy(dest2, src2, 7)
    print(f"Test 2 (Partial): {dest2[:7].decode()}") # Expected: Program

    # Test Case 3: Zero-byte copy
    src3 = bytearray(b"Test")
    dest3 = bytearray(4)
    original_dest3 = dest3[:]
    Lse1.memory_copy(dest3, src3, 0)
    print(f"Test 3 (Zero bytes): {'Unchanged' if dest3 == original_dest3 else 'Changed'}") # Expected: Unchanged

    # Test Case 4: Null input (should not crash)
    src4 = bytearray(b"Test")
    result4 = Lse1.memory_copy(None, src4, 4)
    if result4 is None:
        print("Test 4 (Null input): Handled gracefully")
    else:
        print("Test 4 (Null input): Failed")

    # Test Case 5: Out-of-bounds copy (should not perform the copy)
    src5 = bytearray(b"Small")
    dest5 = bytearray(3)
    original_dest5 = dest5[:]
    result5 = Lse1.memory_copy(dest5, src5, 5) # Attempt to copy 5 bytes into a 3-byte array
    if result5 is None and dest5 == original_dest5:
        print("Test 5 (Out of bounds): Handled correctly")
    else:
        print("Test 5 (Out of bounds): Failed")