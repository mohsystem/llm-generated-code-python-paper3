
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
    tree1 = TreeNode(1)
    tree1.right = TreeNode(2)
    tree1.right.left = TreeNode(3)
    print("Test Case 1:")
    print("Preorder:", preorder_traversal(tree1))
    print("Inorder:", inorder_traversal(tree1))
    print("Postorder:", postorder_traversal(tree1))
    
    # Test Case 2: Balanced tree
    tree2 = TreeNode(1)
    tree2.left = TreeNode(2)
    tree2.right = TreeNode(3)
    tree2.left.left = TreeNode(4)
    tree2.left.right = TreeNode(5)
    print("\\nTest Case 2:")
    print("Preorder:", preorder_traversal(tree2))
    print("Inorder:", inorder_traversal(tree2))
    print("Postorder:", postorder_traversal(tree2))
    
    # Test Case 3: Single node
    tree3 = TreeNode(42)
    print("\\nTest Case 3:")
    print("Preorder:", preorder_traversal(tree3))
    print("Inorder:", inorder_traversal(tree3))
    print("Postorder:", postorder_traversal(tree3))
    
    # Test Case 4: Empty tree
    tree4 = None
    print("\\nTest Case 4:")
    print("Preorder:", preorder_traversal(tree4))
    print("Inorder:", inorder_traversal(tree4))
    print("Postorder:", postorder_traversal(tree4))
    
    # Test Case 5: Left skewed tree
    tree5 = TreeNode(5)
    tree5.left = TreeNode(4)
    tree5.left.left = TreeNode(3)
    tree5.left.left.left = TreeNode(2)
    tree5.left.left.left.left = TreeNode(1)
    print("\\nTest Case 5:")
    print("Preorder:", preorder_traversal(tree5))
    print("Inorder:", inorder_traversal(tree5))
    print("Postorder:", postorder_traversal(tree5))
