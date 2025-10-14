from typing import List, Optional

class TreeNode:
    """Definition for a binary tree node."""
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right

# Preorder Traversal: Root -> Left -> Right
def preorder_traversal(root: Optional[TreeNode]) -> List[int]:
    result = []
    def _preorder(node):
        if not node:
            return
        result.append(node.val)
        _preorder(node.left)
        _preorder(node.right)
    _preorder(root)
    return result

# Inorder Traversal: Left -> Root -> Right
def inorder_traversal(root: Optional[TreeNode]) -> List[int]:
    result = []
    def _inorder(node):
        if not node:
            return
        _inorder(node.left)
        result.append(node.val)
        _inorder(node.right)
    _inorder(root)
    return result

# Postorder Traversal: Left -> Right -> Root
def postorder_traversal(root: Optional[TreeNode]) -> List[int]:
    result = []
    def _postorder(node):
        if not node:
            return
        _postorder(node.left)
        _postorder(node.right)
        result.append(node.val)
    _postorder(root)
    return result

def main():
    """Main function with test cases."""
    # --- Test Case 1: Standard Tree ---
    print("--- Test Case 1 ---")
    root1 = TreeNode(1)
    root1.left = TreeNode(2)
    root1.right = TreeNode(3)
    root1.left.left = TreeNode(4)
    root1.left.right = TreeNode(5)
    print("Preorder: ", preorder_traversal(root1))
    print("Inorder:  ", inorder_traversal(root1))
    print("Postorder:", postorder_traversal(root1))
    print()

    # --- Test Case 2: Null Tree ---
    print("--- Test Case 2 ---")
    root2 = None
    print("Preorder: ", preorder_traversal(root2))
    print("Inorder:  ", inorder_traversal(root2))
    print("Postorder:", postorder_traversal(root2))
    print()

    # --- Test Case 3: Single Node Tree ---
    print("--- Test Case 3 ---")
    root3 = TreeNode(10)
    print("Preorder: ", preorder_traversal(root3))
    print("Inorder:  ", inorder_traversal(root3))
    print("Postorder:", postorder_traversal(root3))
    print()

    # --- Test Case 4: Left-skewed Tree ---
    print("--- Test Case 4 ---")
    root4 = TreeNode(4)
    root4.left = TreeNode(3)
    root4.left.left = TreeNode(2)
    root4.left.left.left = TreeNode(1)
    print("Preorder: ", preorder_traversal(root4))
    print("Inorder:  ", inorder_traversal(root4))
    print("Postorder:", postorder_traversal(root4))
    print()

    # --- Test Case 5: Complex Tree ---
    print("--- Test Case 5 ---")
    root5 = TreeNode(10)
    root5.left = TreeNode(5)
    root5.right = TreeNode(15)
    root5.left.left = TreeNode(3)
    root5.left.right = TreeNode(7)
    root5.right.right = TreeNode(18)
    print("Preorder: ", preorder_traversal(root5))
    print("Inorder:  ", inorder_traversal(root5))
    print("Postorder:", postorder_traversal(root5))
    print()

if __name__ == "__main__":
    main()