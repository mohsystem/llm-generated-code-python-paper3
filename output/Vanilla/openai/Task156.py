from typing import List, Optional

class TreeNode:
    def __init__(self, val: int, left: 'Optional[TreeNode]' = None, right: 'Optional[TreeNode]' = None):
        self.val = val
        self.left = left
        self.right = right

def dfs(root: Optional[TreeNode], order: str) -> List[int]:
    if order is None:
        raise ValueError("order cannot be None")
    order = order.lower()
    if order == "preorder":
        return preorder(root)
    elif order == "inorder":
        return inorder(root)
    elif order == "postorder":
        return postorder(root)
    else:
        raise ValueError(f"Unknown order: {order}")

def preorder(root: Optional[TreeNode]) -> List[int]:
    res: List[int] = []
    def helper(node: Optional[TreeNode]):
        if not node: return
        res.append(node.val)
        helper(node.left)
        helper(node.right)
    helper(root)
    return res

def inorder(root: Optional[TreeNode]) -> List[int]:
    res: List[int] = []
    def helper(node: Optional[TreeNode]):
        if not node: return
        helper(node.left)
        res.append(node.val)
        helper(node.right)
    helper(root)
    return res

def postorder(root: Optional[TreeNode]) -> List[int]:
    res: List[int] = []
    def helper(node: Optional[TreeNode]):
        if not node: return
        helper(node.left)
        helper(node.right)
        res.append(node.val)
    helper(root)
    return res

if __name__ == "__main__":
    # Test 1: Balanced tree
    root1 = TreeNode(1,
            TreeNode(2, TreeNode(4), TreeNode(5)),
            TreeNode(3, TreeNode(6), TreeNode(7)))
    print("Test1 Preorder:", dfs(root1, "preorder"))  # [1,2,4,5,3,6,7]

    # Test 2: Single node
    root2 = TreeNode(10)
    print("Test2 Inorder:", dfs(root2, "inorder"))    # [10]

    # Test 3: Left-skewed
    root3 = TreeNode(5)
    root3.left = TreeNode(4)
    root3.left.left = TreeNode(3)
    root3.left.left.left = TreeNode(2)
    root3.left.left.left.left = TreeNode(1)
    print("Test3 Postorder:", dfs(root3, "postorder")) # [1,2,3,4,5]

    # Test 4: Right-skewed
    root4 = TreeNode(1)
    root4.right = TreeNode(2)
    root4.right.right = TreeNode(3)
    root4.right.right.right = TreeNode(4)
    root4.right.right.right.right = TreeNode(5)
    print("Test4 Preorder:", dfs(root4, "preorder"))   # [1,2,3,4,5]

    # Test 5: Empty tree
    root5 = None
    print("Test5 Inorder (empty):", dfs(root5, "inorder")) # []