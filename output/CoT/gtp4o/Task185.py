# Step 1: Problem Understanding + Step 2: Security Requirements:
# Find median of two sorted arrays in O(log(m+n)) time, with safe handling of edge cases.

def find_median_sorted_arrays(nums1, nums2):
    # Step 3: Secure Coding Generation: input normalization
    if nums1 is None:
        nums1 = []
    if nums2 is None:
        nums2 = []

    # Ensure binary search on the smaller array
    if len(nums1) > len(nums2):
        return find_median_sorted_arrays(nums2, nums1)

    A, B = nums1, nums2
    m, n = len(A), len(B)
    total_left = (m + n + 1) // 2

    lo, hi = 0, m
    while lo <= hi:
        i = (lo + hi) // 2
        j = total_left - i

        left1 = float('-inf') if i == 0 else A[i - 1]
        right1 = float('inf') if i == m else A[i]
        left2 = float('-inf') if j == 0 else B[j - 1]
        right2 = float('inf') if j == n else B[j]

        if left1 <= right2 and left2 <= right1:
            if (m + n) % 2 == 1:
                return float(max(left1, left2))
            else:
                return (max(left1, left2) + min(right1, right2)) / 2.0
        elif left1 > right2:
            hi = i - 1
        else:
            lo = i + 1

    # Step 4: Code Review -> Fallback for unexpected state
    raise ValueError("Invalid input: arrays must be sorted.")

if __name__ == "__main__":
    # Step 5: Secure Code Output with 5 test cases
    tests = [
        ([1, 3], [2]),         # 2.00000
        ([1, 2], [3, 4]),      # 2.50000
        ([], [1]),             # 1.00000
        ([0, 0], [0, 0]),      # 0.00000
        ([-5, -3, -1], [2, 4, 6, 8])  # 2.00000
    ]
    for a, b in tests:
        print("{:.5f}".format(find_median_sorted_arrays(a, b)))