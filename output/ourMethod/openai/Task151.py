from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class _Node:
    key: int
    left: Optional["_Node"] = None
    right: Optional["_Node"] = None

class BST:
    def __init__(self) -> None:
        self._root: Optional[_Node] = None

    def insert(self, key: int) -> bool:
        if not self._is_int_safe(key):
            return False
        if self._root is None:
            self._root = _Node(key)
            return True
        curr = self._root
        parent: Optional[_Node] = None
        while curr is not None:
            if key == curr.key:
                return False
            parent = curr
            if key < curr.key:
                curr = curr.left
            else:
                curr = curr.right
        assert parent is not None
        if key < parent.key:
            parent.left = _Node(key)
        else:
            parent.right = _Node(key)
        return True

    def search(self, key: int) -> bool:
        if not self._is_int_safe(key):
            return False
        curr = self._root
        while curr is not None:
            if key == curr.key:
                return True
            curr = curr.left if key < curr.key else curr.right
        return False

    def delete(self, key: int) -> bool:
        if not self._is_int_safe(key):
            return False
        found = {"val": False}
        self._root = self._delete_rec(self._root, key, found)
        return found["val"]

    def _delete_rec(self, node: Optional[_Node], key: int, found: dict) -> Optional[_Node]:
        if node is None:
            return None
        if key < node.key:
            node.left = self._delete_rec(node.left, key, found)
        elif key > node.key:
            node.right = self._delete_rec(node.right, key, found)
        else:
            found["val"] = True
            if node.left is None:
                return node.right
            if node.right is None:
                return node.left
            succ = self._min_node(node.right)
            new_node = _Node(succ.key, node.left, self._delete_min(node.right))
            return new_node
        return node

    def _min_node(self, node: _Node) -> _Node:
        curr = node
        while curr.left is not None:
            curr = curr.left
        return curr

    def _delete_min(self, node: _Node) -> Optional[_Node]:
        if node.left is None:
            return node.right
        node.left = self._delete_min(node.left)
        return node

    def inorder(self) -> List[int]:
        res: List[int] = []
        self._inorder_rec(self._root, res)
        return res

    def _inorder_rec(self, node: Optional[_Node], res: List[int]) -> None:
        if node is None:
            return
        self._inorder_rec(node.left, res)
        res.append(node.key)
        self._inorder_rec(node.right, res)

    def _is_int_safe(self, value: int) -> bool:
        return isinstance(value, int) and -2_147_483_648 <= value <= 2_147_483_647

def main() -> None:
    bst = BST()

    # Test Case 1: Insert elements and print inorder
    values = [50, 30, 70, 20, 40, 60, 80]
    for v in values:
        print(f"Insert {v}: {bst.insert(v)}")
    print(f"Inorder after inserts: {bst.inorder()}")

    # Test Case 2: Search existing and non-existing keys
    print(f"Search 60: {bst.search(60)}")
    print(f"Search 25: {bst.search(25)}")

    # Test Case 3: Delete a leaf node
    print(f"Delete 20 (leaf): {bst.delete(20)}")
    print(f"Inorder after deleting 20: {bst.inorder()}")

    # Test Case 4: Delete a node with one child
    print(f"Delete 30 (one child): {bst.delete(30)}")
    print(f"Inorder after deleting 30: {bst.inorder()}")

    # Test Case 5: Delete a node with two children and try duplicate insert
    print(f"Delete 50 (two children): {bst.delete(50)}")
    print(f"Inorder after deleting 50: {bst.inorder()}")
    print(f"Insert duplicate 70: {bst.insert(70)}")

if __name__ == "__main__":
    main()