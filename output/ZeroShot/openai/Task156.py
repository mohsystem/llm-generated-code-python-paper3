from typing import List, Optional

class TreeNode:
    __slots__ = ("val", "left", "right")
    def __init__(self, val: int, left: 'Optional[TreeNode]' = None, right: 'Optional[TreeNode]' = None):
        self.val = val
        self.left = left
        self.right = right

def dfs(root: Optional[TreeNode], order: str) -> List[int]:
    if order is None:
        raise ValueError("order cannot be None")
    ord_norm = order.strip().lower()
    if ord_norm == "preorder":
        return _preorder(root)
    elif ord_norm == "inorder":
        return _inorder(root)
    elif ord_norm == "postorder":
        return _postorder(root)
    else:
        raise ValueError(f"Unsupported order: {order}")

def _preorder(root: Optional[TreeNode]) -> List[int]:
    out: List[int] = []
    if root is None:
        return out
    stack = [root]
    while stack:
        node = stack.pop()
        out.append(node.val)
        if node.right is not None:
            stack.append(node.right)
        if node.left is not None:
            stack.append(node.left)
    return out

def _inorder(root: Optional[TreeNode]) -> List[int]:
    out: List[int] = []
    stack: List[TreeNode] = []
    curr = root
    while curr is not None or stack:
        while curr is not None:
            stack.append(curr)
            curr = curr.left
        curr = stack.pop()
        out.append(curr.val)
        curr = curr.right
    return out

def _postorder(root: Optional[TreeNode]) -> List[int]:
    out: List[int] = []
    if root is None:
        return out
    stack: List[TreeNode] = []
    curr: Optional[TreeNode] = root
    last: Optional[TreeNode] = None
    while curr is not None or stack:
        if curr is not None:
            stack.append(curr)
            curr = curr.left
        else:
            peek = stack[-1]
            if peek.right is not None and last is not peek.right:
                curr = peek.right
            else:
                out.append(peek.val)
                last = stack.pop()
    return out

if __name__ == "__main__":
    # Test 1: Empty tree
    t1 = None
    print("Test1 - Preorder (empty):", dfs(t1, "preorder"))

    # Test 2: Single node
    t2 = TreeNode(42)
    print("Test2 - Inorder (single):", dfs(t2, "inorder"))

    # Test 3: Balanced tree
    t3 = TreeNode(4,
         left=TreeNode(2, TreeNode(1), TreeNode(3)),
         right=TreeNode(6, TreeNode(5), TreeNode(7)))
    print("Test3 - Inorder (balanced):", dfs(t3, "inorder"))

    # Test 4: Left-skewed
    t4 = TreeNode(5, TreeNode(4, TreeNode(3, TreeNode(2, TreeNode(1)))))
    print("Test4 - Postorder (left-skewed):", dfs(t4, "postorder"))
