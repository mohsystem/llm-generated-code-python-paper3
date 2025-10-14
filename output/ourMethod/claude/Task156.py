
from typing import List, Optional

class TreeNode:
    def __init__(self, value: int):
        self.value: int = value
        self.left: Optional[TreeNode] = None
        self.right: Optional[TreeNode] = None

def preorder_traversal(root: Optional[TreeNode]) -> List[int]:
    result: List[int] = []
    if root is None:
        return result
    _preorder_helper(root, result)
    return result

def _preorder_helper(node: Optional[TreeNode], result: List[int]) -> None:
    if node is None:
        return
    result.append(node.value)
    _preorder_helper(node.left, result)
    _preorder_helper(node.right, result)

def inorder_traversal(root: Optional[TreeNode]) -> List[int]:
    result: List[int] = []
    if root is None:
        return result
    _inorder_helper(root, result)
    return result

def _inorder_helper(node: Optional[TreeNode], result: List[int]) -> None:
    if node is None:
        return
    _inorder_helper(node.left, result)
    result.append(node.value)
    _inorder_helper(node.right, result)

def postorder_traversal(root: Optional[TreeNode]) -> List[int]:
    result: List[int] = []
    if root is None:
        return result
    _postorder_helper(root, result)
    return result

def _postorder_helper(node: Optional[TreeNode], result: List[int]) -> None:
    if node is None:
        return
    _postorder_helper(node.left, result)
    _postorder_helper(node.right, result)
    result.append(node.value)

if __name__ == "__main__":
    # Test case 1: Single node tree
    tree1 = TreeNode(1)
    print("Test 1 - Preorder:", preorder_traversal(tree1))
    print("Test 1 - Inorder:", inorder_traversal(tree1))
    print("Test 1 - Postorder:", postorder_traversal(tree1))
    
    # Test case 2: Empty tree
    tree2 = None
    print("Test 2 - Preorder:", preorder_traversal(tree2))
    print("Test 2 - Inorder:", inorder_traversal(tree2))
    print("Test 2 - Postorder:", postorder_traversal(tree2))
    
    # Test case 3: Left-skewed tree
    tree3 = TreeNode(1)
    tree3.left = TreeNode(2)
    tree3.left.left = TreeNode(3)
    print("Test 3 - Preorder:", preorder_traversal(tree3))
    print("Test 3 - Inorder:", inorder_traversal(tree3))
    print("Test 3 - Postorder:", postorder_traversal(tree3))
    
    # Test case 4: Right-skewed tree
    tree4 = TreeNode(1)
    tree4.right = TreeNode(2)
    tree4.right.right = TreeNode(3)
    print("Test 4 - Preorder:", preorder_traversal(tree4))
    print("Test 4 - Inorder:", inorder_traversal(tree4))
    print("Test 4 - Postorder:", postorder_traversal(tree4))
    
    # Test case 5: Balanced tree
    tree5 = TreeNode(1)
    tree5.left = TreeNode(2)
    tree5.right = TreeNode(3)
    tree5.left.left = TreeNode(4)
    tree5.left.right = TreeNode(5)
    tree5.right.left = TreeNode(6)
    tree5.right.right = TreeNode(7)
    print("Test 5 - Preorder:", preorder_traversal(tree5))
    print("Test 5 - Inorder:", inorder_traversal(tree5))
    print("Test 5 - Postorder:", postorder_traversal(tree5))
