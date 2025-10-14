from typing import List

class Task169:
    def countSmaller(self, nums: List[int]) -> List[int]:
        n = len(nums)
        if n == 0:
            return []
        
        items = [(nums[i], i) for i in range(n)]
        counts = [0] * n

        def merge_sort_and_count(arr_slice):
            if len(arr_slice) <= 1:
                return arr_slice

            mid = len(arr_slice) // 2
            left = merge_sort_and_count(arr_slice[:mid])
            right = merge_sort_and_count(arr_slice[mid:])
            
            merged = []
            i, j = 0, 0
            
            while i < len(left) and j < len(right):
                if left[i][0] <= right[j][0]:
                    counts[left[i][1]] += j
                    merged.append(left[i])
                    i += 1
                else:
                    merged.append(right[j])
                    j += 1

            while i < len(left):
                counts[left[i][1]] += len(right)
                merged.append(left[i])
                i += 1
            
            while j < len(right):
                merged.append(right[j])
                j += 1
                
            return merged

        merge_sort_and_count(items)
        return counts

def main():
    solver = Task169()

    # Test Case 1
    nums1 = [5, 2, 6, 1]
    print(f"Test Case 1: nums = {nums1}, Output: {solver.countSmaller(nums1)}")

    # Test Case 2
    nums2 = [-1]
    print(f"Test Case 2: nums = {nums2}, Output: {solver.countSmaller(nums2)}")

    # Test Case 3
    nums3 = [-1, -1]
    print(f"Test Case 3: nums = {nums3}, Output: {solver.countSmaller(nums3)}")

    # Test Case 4
    nums4 = [5, 4, 3, 2, 1]
    print(f"Test Case 4: nums = {nums4}, Output: {solver.countSmaller(nums4)}")
    
    # Test Case 5
    nums5 = []
    print(f"Test Case 5: nums = {nums5}, Output: {solver.countSmaller(nums5)}")

if __name__ == "__main__":
    main()