def count_reverse_pairs(nums):
    if nums is None or len(nums) <= 1:
        return 0

    arr = list(nums)
    n = len(arr)
    temp = [0] * n

    def merge_sort(left, right):
        if left >= right:
            return 0
        mid = (left + right) // 2
        count = merge_sort(left, mid) + merge_sort(mid + 1, right)

        j = mid + 1
        for i in range(left, mid + 1):
            while j <= right and arr[i] > 2 * arr[j]:
                j += 1
            count += (j - (mid + 1))

        i, j, k = left, mid + 1, left
        while i <= mid and j <= right:
            if arr[i] <= arr[j]:
                temp[k] = arr[i]
                i += 1
            else:
                temp[k] = arr[j]
                j += 1
            k += 1
        while i <= mid:
            temp[k] = arr[i]
            i += 1
            k += 1
        while j <= right:
            temp[k] = arr[j]
            j += 1
            k += 1
        for idx in range(left, right + 1):
            arr[idx] = temp[idx]

        return count

    return merge_sort(0, n - 1)


if __name__ == "__main__":
    tests = [
        [1, 3, 2, 3, 1],
        [2, 4, 3, 5, 1],
        [1],
        [2147483647, -2147483648, 0],
        [-5, -5],
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} result: {count_reverse_pairs(t)}")