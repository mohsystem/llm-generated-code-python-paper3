def heap_sort(arr):
    a = list(arr)
    n = len(a)

    def heapify(size, i):
        while True:
            largest = i
            l = 2 * i + 1
            r = 2 * i + 2
            if l < size and a[l] > a[largest]:
                largest = l
            if r < size and a[r] > a[largest]:
                largest = r
            if largest != i:
                a[i], a[largest] = a[largest], a[i]
                i = largest
            else:
                break

    for i in range(n // 2 - 1, -1, -1):
        heapify(n, i)
    for i in range(n - 1, 0, -1):
        a[0], a[i] = a[i], a[0]
        heapify(i, 0)
    return a


if __name__ == "__main__":
    tests = [
        [4, 10, 3, 5, 1],
        [],
        [1],
        [9, -2, 0, 7, 3, 3, -5],
        [5, 4, 3, 2, 1],
    ]
    for t in tests:
        print(heap_sort(t))