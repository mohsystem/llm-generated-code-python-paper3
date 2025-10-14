
class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right

def preorder_traversal(root):
    result = []
    preorder_helper(root, result)
    return result

def preorder_helper(node, result):
    if node is None:
        return
    result.append(node.val)
    preorder_helper(node.left, result)
    preorder_helper(node.right, result)

def inorder_traversal(root):
    result = []
    inorder_helper(root, result)
    return result

def inorder_helper(node, result):
    if node is None:
        return
    inorder_helper(node.left, result)
    result.append(node.val)
    inorder_helper(node.right, result)

def postorder_traversal(root):
    result = []
    postorder_helper(root, result)
    return result

def postorder_helper(node, result):
    if node is None:
        return
    postorder_helper(node.left, result)
    postorder_helper(node.right, result)
    result.append(node.val)

if __name__ == "__main__":
    # Test Case 1: Simple tree
    root1 = TreeNode(1)
    root1.left = TreeNode(2)
    root1.right = TreeNode(3)
    print("Test Case 1:")
    print("Preorder:", preorder_traversal(root1))
    print("Inorder:", inorder_traversal(root1))
    print("Postorder:", postorder_traversal(root1))
    print()
    
    # Test Case 2: Left-skewed tree
    root2 = TreeNode(1)
    root2.left = TreeNode(2)
    root2.left.left = TreeNode(3)
    print("Test Case 2:")
    print("Preorder:", preorder_traversal(root2))
    print("Inorder:", inorder_traversal(root2))
    print("Postorder:", postorder_traversal(root2))
    print()
    
    # Test Case 3: Right-skewed tree
    root3 = TreeNode(1)
    root3.right = TreeNode(2)
    root3.right.right = TreeNode(3)
    print("Test Case 3:")
    print("Preorder:", preorder_traversal(root3))
    print("Inorder:", inorder_traversal(root3))
    print("Postorder:", postorder_traversal(root3))
    print()
    
    # Test Case 4: Complete binary tree
    root4 = TreeNode(1)
    root4.left = TreeNode(2)
    root4.right = TreeNode(3)
    root4.left.left = TreeNode(4)
    root4.left.right = TreeNode(5)
    root4.right.left = TreeNode(6)
    root4.right.right = TreeNode(7)
    print("Test Case 4:")
    print("Preorder:", preorder_traversal(root4))
    print("Inorder:", inorder_traversal(root4))
    print("Postorder:", postorder_traversal(root4))
    print()
    
    # Test Case 5: Empty tree
    root5 = None
    print("Test Case 5:")
    print("Preorder:", preorder_traversal(root5))
    print("Inorder:", inorder_traversal(root5))
    print("Postorder:", postorder_traversal(root5))
