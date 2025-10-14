from typing import List, Optional

class Task155:
    @staticmethod
    def heap_sort(arr: Optional[List[int]]) -> List[int]:
        if arr is None:
            return []
        a = list(arr)
        n = len(a)

        def sift_down(n_local: int, i: int) -> None:
            while True:
                largest = i
                left = 2 * i + 1
                right = left + 1

                if left < n_local and a[left] > a[largest]:
                    largest = left
                if right < n_local and a[right] > a[largest]:
                    largest = right
                if largest == i:
                    break
                a[i], a[largest] = a[largest], a[i]
                i = largest

        # Build max heap
        for i in range(n // 2 - 1, -1, -1):
            sift_down(n, i)

        # Extract from heap
        for end in range(n - 1, 0, -1):
            a[0], a[end] = a[end], a[0]
            sift_down(end, 0)

        return a

if __name__ == "__main__":
    tests = [
        [],
        [1],
        [5, 3, 8, 4, 2, 7, 1, 10],
        [1, 2, 3, 4, 5],
        [-3, -1, -7, 0, 2, 2, -3],
    ]
    for t in tests:
        print(Task155.heap_sort(t))