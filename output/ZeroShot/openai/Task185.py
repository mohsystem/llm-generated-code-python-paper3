class Task185:
    @staticmethod
    def findMedianSortedArrays(nums1, nums2):
        A = nums1 or []
        B = nums2 or []
        if len(A) > len(B):
            A, B = B, A
        m, n = len(A), len(B)
        total_left = (m + n + 1) // 2

        lo, hi = 0, m
        neg_inf, pos_inf = float('-inf'), float('inf')

        while lo <= hi:
            i = (lo + hi) // 2
            j = total_left - i

            leftA = neg_inf if i == 0 else A[i - 1]
            rightA = pos_inf if i == m else A[i]
            leftB = neg_inf if j == 0 else B[j - 1]
            rightB = pos_inf if j == n else B[j]

            if leftA <= rightB and leftB <= rightA:
                if (m + n) % 2 == 1:
                    return float(max(leftA, leftB))
                else:
                    return (max(leftA, leftB) + min(rightA, rightB)) / 2.0
            elif leftA > rightB:
                hi = i - 1
            else:
                lo = i + 1
        raise ValueError("Invalid input arrays.")

if __name__ == "__main__":
    print(f"{Task185.findMedianSortedArrays([1,3],[2]):.5f}")
    print(f"{Task185.findMedianSortedArrays([1,2],[3,4]):.5f}")
    print(f"{Task185.findMedianSortedArrays([], [1]):.5f}")
    print(f"{Task185.findMedianSortedArrays([0,0],[0,0]):.5f}")
    print(f"{Task185.findMedianSortedArrays([2], []):.5f}")