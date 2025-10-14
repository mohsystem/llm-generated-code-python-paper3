
class TreeNode:
    def __init__(self, val):
        self.val = val
        self.count = 1
        self.left_size = 0
        self.left = None
        self.right = None

def countSmaller(nums):
    if not nums:
        return []
    
    result = [0] * len(nums)
    root = None
    
    for i in range(len(nums) - 1, -1, -1):
        root = insert(root, nums[i], result, i, 0)
    
    return result

def insert(node, val, result, index, pre_sum):
    if node is None:
        node = TreeNode(val)
        result[index] = pre_sum
    elif node.val == val:
        node.count += 1
        result[index] = pre_sum + node.left_size
    elif node.val > val:
        node.left_size += 1
        node.left = insert(node.left, val, result, index, pre_sum)
    else:
        node.right = insert(node.right, val, result, index, pre_sum + node.left_size + node.count)
    return node

if __name__ == "__main__":
    # Test case 1
    nums1 = [5, 2, 6, 1]
    print("Test 1:", countSmaller(nums1))
    
    # Test case 2
    nums2 = [-1]
    print("Test 2:", countSmaller(nums2))
    
    # Test case 3
    nums3 = [-1, -1]
    print("Test 3:", countSmaller(nums3))
    
    # Test case 4
    nums4 = [1, 2, 3, 4, 5]
    print("Test 4:", countSmaller(nums4))
    
    # Test case 5
    nums5 = [5, 4, 3, 2, 1]
    print("Test 5:", countSmaller(nums5))
