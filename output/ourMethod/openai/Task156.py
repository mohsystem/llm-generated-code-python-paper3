from typing import List, Optional, Tuple


class TreeNode:
    __slots__ = ("val", "left", "right")
    def __init__(self, val: int) -> None:
        self.val: int = val
        self.left: Optional["TreeNode"] = None
        self.right: Optional["TreeNode"] = None


def build_tree(values: List[int], present: List[bool]) -> Optional[TreeNode]:
    if values is None or present is None:
        raise ValueError("values/present cannot be None")
    if len(values) != len(present):
        raise ValueError("values and present must have same length")
    n = len(values)
    if n == 0:
        return None
    if not present[0]:
        return None
    nodes: List[Optional[TreeNode]] = [None] * n
    for i in range(n):
        if present[i]:
            nodes[i] = TreeNode(values[i])
    for i in range(n):
        if nodes[i] is None:
            continue
        li = 2 * i + 1
        ri = 2 * i + 2
        if li < n and nodes[li] is not None:
            nodes[i].left = nodes[li]
        if ri < n and nodes[ri] is not None:
            nodes[i].right = nodes[ri]
    return nodes[0]


def traverse(root: Optional[TreeNode], order: str) -> List[int]:
    if order is None:
        raise ValueError("order cannot be None")
    o = order.lower()
    out: List[int] = []
    if o == "preorder":
        _preorder(root, out)
    elif o == "inorder":
        _inorder(root, out)
    elif o == "postorder":
        _postorder(root, out)
    else:
        raise ValueError(f"Unsupported order: {order}")
    return out


def _preorder(node: Optional[TreeNode], out: List[int]) -> None:
    if node is None:
        return
    out.append(node.val)
    _preorder(node.left, out)
    _preorder(node.right, out)


def _inorder(node: Optional[TreeNode], out: List[int]) -> None:
    if node is None:
        return
    _inorder(node.left, out)
    out.append(node.val)
    _inorder(node.right, out)


def _postorder(node: Optional[TreeNode], out: List[int]) -> None:
    if node is None:
        return
    _postorder(node.left, out)
    _postorder(node.right, out)
    out.append(node.val)


def _format(lst: List[int]) -> str:
    return "[" + ",".join(str(x) for x in lst) + "]"


def main() -> None:
    tests_values: List[List[int]] = [
        [1,2,3,4,5,6,7],
        [1,2,3,0,5,0,7],
        [42],
        [],
        [1,0,2,0,0,0,3],
    ]
    tests_present: List[List[bool]] = [
        [True,True,True,True,True,True,True],
        [True,True,True,False,True,False,True],
        [True],
        [],
        [True,False,True,False,False,False,True],
    ]
    orders = ["preorder", "inorder", "postorder"]

    for idx, (vals, pres) in enumerate(zip(tests_values, tests_present), start=1):
        print(f"Test #{idx}")
        try:
            root = build_tree(vals, pres)
            for ord in orders:
                res = traverse(root, ord)
                print(f"{ord}: {_format(res)}")
        except ValueError as e:
            print(f"Error: {e}")
        print()

if __name__ == "__main__":
    main()