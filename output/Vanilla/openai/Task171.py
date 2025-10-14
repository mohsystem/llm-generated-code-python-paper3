def reverse_pairs(nums):
    def sort_count(a, l, r, temp):
        if l >= r:
            return 0
        m = (l + r) // 2
        cnt = sort_count(a, l, m, temp) + sort_count(a, m + 1, r, temp)

        j = m + 1
        for i in range(l, m + 1):
            while j <= r and a[i] > 2 * a[j]:
                j += 1
            cnt += j - (m + 1)

        i, j, k = l, m + 1, l
        while i <= m and j <= r:
            if a[i] <= a[j]:
                temp[k] = a[i]
                i += 1
            else:
                temp[k] = a[j]
                j += 1
            k += 1
        while i <= m:
            temp[k] = a[i]
            i += 1
            k += 1
        while j <= r:
            temp[k] = a[j]
            j += 1
            k += 1
        for t in range(l, r + 1):
            a[t] = temp[t]
        return cnt

    if not nums:
        return 0
    temp = [0] * len(nums)
    return sort_count(nums[:], 0, len(nums) - 1, temp)


if __name__ == "__main__":
    print(reverse_pairs([1, 3, 2, 3, 1]))                 # 2
    print(reverse_pairs([2, 4, 3, 5, 1]))                 # 3
    print(reverse_pairs([-5, -5]))                        # 1
    print(reverse_pairs([2147483647, -2147483648, 0]))    # 2
    print(reverse_pairs([5, 4, 3, 2, 1]))                 # 4