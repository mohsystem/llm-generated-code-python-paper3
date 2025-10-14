from typing import Optional, List

class TreeNode:
    def __init__(self, val: int = 0, left: 'Optional[TreeNode]' = None, right: 'Optional[TreeNode]' = None):
        self.val = val
        self.left = left
        self.right = right

def preorder_traversal(root: Optional[TreeNode]) -> List[int]:
    """Performs preorder traversal (Root -> Left -> Right)."""
    result: List[int] = []
    
    def traverse(node: Optional[TreeNode]):
        if node is None:
            return
        result.append(node.val)
        traverse(node.left)
        traverse(node.right)
        
    traverse(root)
    return result

def inorder_traversal(root: Optional[TreeNode]) -> List[int]:
    """Performs inorder traversal (Left -> Root -> Right)."""
    result: List[int] = []
    
    def traverse(node: Optional[TreeNode]):
        if node is None:
            return
        traverse(node.left)
        result.append(node.val)
        traverse(node.right)
        
    traverse(root)
    return result

def postorder_traversal(root: Optional[TreeNode]) -> List[int]:
    """Performs postorder traversal (Left -> Right -> Root)."""
    result: List[int] = []
    
    def traverse(node: Optional[TreeNode]):
        if node is None:
            return
        traverse(node.left)
        traverse(node.right)
        result.append(node.val)
        
    traverse(root)
    return result

def run_test_case(name: str, root: Optional[TreeNode]):
    print(f"--- {name} ---")
    print(f"Preorder:  {preorder_traversal(root)}")
    print(f"Inorder:   {inorder_traversal(root)}")
    print(f"Postorder: {postorder_traversal(root)}")
    print()

def main():
    # Test Case 1: A balanced binary tree
    root1 = TreeNode(4)
    root1.left = TreeNode(2)
    root1.right = TreeNode(7)
    root1.left.left = TreeNode(1)
    root1.left.right = TreeNode(3)
    root1.right.left = TreeNode(6)
    root1.right.right = TreeNode(9)
    run_test_case("Test Case 1: Balanced Tree", root1)

    # Test Case 2: A left-skewed tree
    root2 = TreeNode(3)
    root2.left = TreeNode(2)
    root2.left.left = TreeNode(1)
    run_test_case("Test Case 2: Left-Skewed Tree", root2)

    # Test Case 3: A right-skewed tree
    root3 = TreeNode(1)
    root3.right = TreeNode(2)
    root3.right.right = TreeNode(3)
    run_test_case("Test Case 3: Right-Skewed Tree", root3)
    
    # Test Case 4: A single node tree
    root4 = TreeNode(5)
    run_test_case("Test Case 4: Single Node Tree", root4)

    # Test Case 5: An empty tree
    root5 = None
    run_test_case("Test Case 5: Empty Tree", root5)

if __name__ == "__main__":
    main()