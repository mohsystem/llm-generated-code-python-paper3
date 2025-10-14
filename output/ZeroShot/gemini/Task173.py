class Task173:
    def longestDupSubstring(self, s: str) -> str:
        """
        Finds the longest duplicated substring in a string.
        :param s: The input string.
        :return: The longest duplicated substring, or "" if none exists.
        """
        n = len(s)
        # Convert string to a list of integers for easier hash calculation
        nums = [ord(c) - ord('a') + 1 for c in s]
        base = 29
        # Use a large prime modulus to minimize collisions
        mod = (1 << 61) - 1

        def check(length: int) -> int:
            """
            Checks if a duplicated substring of a given length exists using a rolling hash.
            :param length: The length of the substring to check for.
            :return: The starting index of a duplicated substring, or -1 if none.
            """
            if length == 0:
                return 0
            if length >= n:
                return -1

            h = pow(base, length, mod)
            current_hash = 0
            for i in range(length):
                current_hash = (current_hash * base + nums[i]) % mod

            seen = {current_hash}
            for i in range(1, n - length + 1):
                # Rolling hash update
                current_hash = (current_hash * base - nums[i - 1] * h + nums[i + length - 1]) % mod
                
                if current_hash in seen:
                    # Found a potential duplicate.
                    return i
                seen.add(current_hash)
            return -1

        ans = ""
        low, high = 1, n - 1
        
        # Binary search for the length of the longest duplicated substring
        while low <= high:
            mid = low + (high - low) // 2
            if mid == 0: break
            
            start_index = check(mid)
            if start_index != -1:
                ans = s[start_index : start_index + mid]
                low = mid + 1  # Try for a longer substring
            else:
                high = mid - 1  # Substring length is too long
        
        return ans

if __name__ == '__main__':
    solver = Task173()
    test_cases = [
        "banana",
        "abcd",
        "ababa",
        "aaaaa",
        "mississippi"
    ]
    
    for s in test_cases:
        result = solver.longestDupSubstring(s)
        print(f"Input: s = \"{s}\"")
        print(f"Output: \"{result}\"")
        print()