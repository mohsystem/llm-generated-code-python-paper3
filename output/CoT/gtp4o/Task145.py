# Task145 - Python implementation
# Chain-of-Through process:
# 1) Problem: Return maximum sum of any contiguous subarray.
# 2) Security: Handle None/empty; Python ints are unbounded.
# 3) Secure coding: Pure function; no external input.
# 4) Code review: Handles all-negative and empty arrays.
# 5) Final secure output.

def max_sub_array(nums):
    if nums is None or len(nums) == 0:
        return 0
    best = None
    curr = 0
    for x in nums:
        curr = max(x, curr + x)
        best = curr if best is None or curr > best else best
    return best

if __name__ == "__main__":
    # 5 test cases
    print(max_sub_array([1, -3, 2, 1, -1]))      # 3
    print(max_sub_array([-2, -3, -1, -4]))       # -1
    print(max_sub_array([5]))                    # 5
    print(max_sub_array([]))                     # 0
    print(max_sub_array([4, -1, 2, 1, -5, 4]))   # 6