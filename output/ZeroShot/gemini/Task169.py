from typing import List

class Task169:
    def countSmaller(self, nums: List[int]) -> List[int]:
        n = len(nums)
        if n == 0:
            return []
        
        counts = [0] * n
        pairs = [(nums[i], i) for i in range(n)]

        def merge_sort(arr, start, end):
            if start >= end:
                return
            
            mid = start + (end - start) // 2
            merge_sort(arr, start, mid)
            merge_sort(arr, mid + 1, end)
            merge(arr, start, mid, end)

        def merge(arr, start, mid, end):
            temp = []
            i, j = start, mid + 1
            right_elements_smaller = 0
            
            while i <= mid and j <= end:
                if arr[i][0] > arr[j][0]:
                    temp.append(arr[j])
                    right_elements_smaller += 1
                    j += 1
                else:
                    counts[arr[i][1]] += right_elements_smaller
                    temp.append(arr[i])
                    i += 1
            
            while i <= mid:
                counts[arr[i][1]] += right_elements_smaller
                temp.append(arr[i])
                i += 1
                
            while j <= end:
                temp.append(arr[j])
                j += 1
                
            for k in range(len(temp)):
                arr[start + k] = temp[k]

        merge_sort(pairs, 0, n - 1)
        return counts

# Main method with test cases
if __name__ == '__main__':
    solution = Task169()

    # Test Case 1
    nums1 = [5, 2, 6, 1]
    print(f"Test Case 1: {solution.countSmaller(nums1)}")

    # Test Case 2
    nums2 = [-1]
    print(f"Test Case 2: {solution.countSmaller(nums2)}")

    # Test Case 3
    nums3 = [-1, -1]
    print(f"Test Case 3: {solution.countSmaller(nums3)}")

    # Test Case 4
    nums4 = []
    print(f"Test Case 4: {solution.countSmaller(nums4)}")

    # Test Case 5
    nums5 = [2, 0, 1]
    print(f"Test Case 5: {solution.countSmaller(nums5)}")