
class TreeNode:
    def __init__(self, val):
        if not isinstance(val, int):
            raise TypeError("Node value must be an integer")
        self.val = val
        self.left = None
        self.right = None

def preorder_traversal(root):
    result = []
    if root is None:
        return result
    
    def preorder_helper(node):
        if node is None:
            return
        result.append(node.val)
        preorder_helper(node.left)
        preorder_helper(node.right)
    
    preorder_helper(root)
    return result

def inorder_traversal(root):
    result = []
    if root is None:
        return result
    
    def inorder_helper(node):
        if node is None:
            return
        inorder_helper(node.left)
        result.append(node.val)
        inorder_helper(node.right)
    
    inorder_helper(root)
    return result

def postorder_traversal(root):
    result = []
    if root is None:
        return result
    
    def postorder_helper(node):
        if node is None:
            return
        postorder_helper(node.left)
        postorder_helper(node.right)
        result.append(node.val)
    
    postorder_helper(root)
    return result

if __name__ == "__main__":
    # Test Case 1: Single node tree
    test1 = TreeNode(1)
    print("Test 1 - Preorder:", preorder_traversal(test1))
    print("Test 1 - Inorder:", inorder_traversal(test1))
    print("Test 1 - Postorder:", postorder_traversal(test1))
    
    # Test Case 2: Balanced tree
    test2 = TreeNode(1)
    test2.left = TreeNode(2)
    test2.right = TreeNode(3)
    test2.left.left = TreeNode(4)
    test2.left.right = TreeNode(5)
    print("\\nTest 2 - Preorder:", preorder_traversal(test2))
    print("Test 2 - Inorder:", inorder_traversal(test2))
    print("Test 2 - Postorder:", postorder_traversal(test2))
    
    # Test Case 3: Left-skewed tree
    test3 = TreeNode(1)
    test3.left = TreeNode(2)
    test3.left.left = TreeNode(3)
    print("\\nTest 3 - Preorder:", preorder_traversal(test3))
    print("Test 3 - Inorder:", inorder_traversal(test3))
    print("Test 3 - Postorder:", postorder_traversal(test3))
    
    # Test Case 4: Right-skewed tree
    test4 = TreeNode(1)
    test4.right = TreeNode(2)
    test4.right.right = TreeNode(3)
    print("\\nTest 4 - Preorder:", preorder_traversal(test4))
    print("Test 4 - Inorder:", inorder_traversal(test4))
    print("Test 4 - Postorder:", postorder_traversal(test4))
    
    # Test Case 5: Empty tree
    test5 = None
    print("\\nTest 5 - Preorder:", preorder_traversal(test5))
    print("Test 5 - Inorder:", inorder_traversal(test5))
    print("Test 5 - Postorder:", postorder_traversal(test5))
