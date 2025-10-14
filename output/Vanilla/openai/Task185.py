def findMedianSortedArrays(nums1, nums2):
    if len(nums1) > len(nums2):
        nums1, nums2 = nums2, nums1
    m, n = len(nums1), len(nums2)
    imin, imax, half = 0, m, (m + n + 1) // 2
    while imin <= imax:
        i = (imin + imax) // 2
        j = half - i
        if i < m and j > 0 and nums2[j - 1] > nums1[i]:
            imin = i + 1
        elif i > 0 and j < n and nums1[i - 1] > nums2[j]:
            imax = i - 1
        else:
            if i == 0:
                maxLeft = nums2[j - 1]
            elif j == 0:
                maxLeft = nums1[i - 1]
            else:
                maxLeft = max(nums1[i - 1], nums2[j - 1])
            if (m + n) % 2 == 1:
                return float(maxLeft)
            if i == m:
                minRight = nums2[j]
            elif j == n:
                minRight = nums1[i]
            else:
                minRight = min(nums1[i], nums2[j])
            return (maxLeft + minRight) / 2.0

if __name__ == "__main__":
    tests = [
        ([1,3], [2]),
        ([1,2], [3,4]),
        ([], [1]),
        ([0,0], [0,0]),
        ([2], []),
    ]
    for a, b in tests:
        print(f"{findMedianSortedArrays(a, b):.5f}")