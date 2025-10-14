# The main class is named Task173 as per instructions
class Task173:
    def longestDupSubstring(self, s: str) -> str:
        n = len(s)
        nums = [ord(c) - ord('a') for c in s]
        base = 26
        # Using a large prime modulus to reduce collisions
        modulus = 2**63 - 1

        def search(length: int) -> int:
            """
            Searches for a duplicated substring of a specific length using rolling hash.
            Returns the starting index of a duplicate, or -1 if not found.
            """
            if length == 0:
                return 0
            if length >= n:
                return -1

            # Calculate base^(length-1) % modulus for removing the leading character
            high_power = pow(base, length - 1, modulus)
            
            current_hash = 0
            # Calculate hash of the first window
            for i in range(length):
                current_hash = (current_hash * base + nums[i]) % modulus
            
            seen = {current_hash}
            
            # Slide the window across the string
            for i in range(1, n - length + 1):
                # Update hash in O(1)
                current_hash = ((current_hash - nums[i-1] * high_power) * base + nums[i + length - 1]) % modulus
                
                if current_hash in seen:
                    # Found a potential duplicate based on hash.
                    return i
                seen.add(current_hash)
            return -1

        # Binary search for the length of the substring
        low, high = 1, n - 1
        start = -1
        max_len = 0
        
        while low <= high:
            mid = low + (high - low) // 2
            if mid == 0: break
            found_start = search(mid)
            if found_start != -1:
                # Found a duplicate, store it and try for a longer one
                max_len = mid
                start = found_start
                low = mid + 1
            else:
                # No duplicate of this length, try a shorter one
                high = mid - 1
        
        if start == -1:
            return ""
        return s[start : start + max_len]

if __name__ == '__main__':
    solver = Task173()
    
    test_cases = {
        "banana": "ana",
        "abcd": "",
        "ababa": "aba",
        "zzzzzzzzzz": "zzzzzzzzz",
        "mississippi": "issi"
    }

    for i, (s, expected) in enumerate(test_cases.items()):
        result = solver.longestDupSubstring(s)
        print(f"Test Case {i+1}:")
        print(f"Input: s = \"{s}\"")
        print(f"Output: \"{result}\"")
        print(f"Expected: \"{expected}\"")
        print()