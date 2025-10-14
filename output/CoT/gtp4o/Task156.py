# Chain-of-Through process embedded via comments:
# 1) Problem: Implement DFS (preorder, inorder, postorder) returning list of values.
# 2) Security: Validate traversal order, avoid recursion depth with iterative approach.
# 3) Secure coding: Defensive checks, no global mutable state reliance.
# 4) Review: Ensure robust handling of None and invalid inputs.
# 5) Output: Iterative traversals and safe tree construction.

from collections import deque
from typing import List, Optional

class Node:
    __slots__ = ("val", "left", "right")
    def __init__(self, val: int):
        self.val: int = val
        self.left: Optional["Node"] = None
        self.right: Optional["Node"] = None

def normalize_order(order: Optional[str]) -> str:
    if not order:
        return "preorder"
    o = order.strip().lower()
    return o if o in ("preorder", "inorder", "postorder") else "preorder"

def dfs(root: Optional[Node], order: str) -> List[int]:
    ordn = normalize_order(order)
    res: List[int] = []
    if root is None:
        return res
    if ordn == "preorder":
        st: List[Node] = [root]
        while st:
            n = st.pop()
            res.append(n.val)
            if n.right: st.append(n.right)
            if n.left: st.append(n.left)
    elif ordn == "inorder":
        st: List[Node] = []
        cur = root
        while cur or st:
            while cur:
                st.append(cur)
                cur = cur.left
            n = st.pop()
            res.append(n.val)
            cur = n.right
    else:  # postorder
        st: List[Node] = []
        cur = root
        last = None
        while cur or st:
            if cur:
                st.append(cur)
                cur = cur.left
            else:
                peek = st[-1]
                if peek.right and last is not peek.right:
                    cur = peek.right
                else:
                    res.append(peek.val)
                    last = st.pop()
    return res

def build_tree_from_level_order(arr: List[Optional[int]]) -> Optional[Node]:
    if not arr or arr[0] is None:
        return None
    root = Node(arr[0])
    q: deque[Node] = deque([root])
    i = 1
    while q and i < len(arr):
        node = q.popleft()
        if i < len(arr) and arr[i] is not None:
            node.left = Node(arr[i])
            q.append(node.left)
        i += 1
        if i < len(arr) and arr[i] is not None:
            node.right = Node(arr[i])
            q.append(node.right)
        i += 1
    return root

def _list_str(lst: List[int]) -> str:
    return "[" + ", ".join(str(x) for x in lst) + "]"

# 5 test cases
if __name__ == "__main__":
    tests = [
        [1, 2, 3, 4, 5, None, 6],
        [1, None, 2, 3],
        [],
        [10, 5, 15, None, 7, 12, 20],
        [42],
    ]
    orders = ["preorder", "inorder", "postorder"]
    for i, t in enumerate(tests, 1):
        root = build_tree_from_level_order(t)
        print(f"Case {i}:")
        for o in orders:
            print(f" {o}: {_list_str(dfs(root, o))}")