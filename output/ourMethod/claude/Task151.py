
from typing import Optional, List

class Node:
    def __init__(self, value: int):
        self.value: int = value
        self.left: Optional[Node] = None
        self.right: Optional[Node] = None

class BST:
    MAX_SIZE: int = 100000

    def __init__(self):
        self.root: Optional[Node] = None
        self.size: int = 0

    def insert(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        if self.size >= self.MAX_SIZE:
            return False
        if self.root is None:
            self.root = Node(value)
            self.size += 1
            return True
        return self._insert_helper(self.root, value)

    def _insert_helper(self, node: Node, value: int) -> bool:
        if value == node.value:
            return False
        if value < node.value:
            if node.left is None:
                node.left = Node(value)
                self.size += 1
                return True
            return self._insert_helper(node.left, value)
        else:
            if node.right is None:
                node.right = Node(value)
                self.size += 1
                return True
            return self._insert_helper(node.right, value)

    def search(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        return self._search_helper(self.root, value)

    def _search_helper(self, node: Optional[Node], value: int) -> bool:
        if node is None:
            return False
        if value == node.value:
            return True
        if value < node.value:
            return self._search_helper(node.left, value)
        else:
            return self._search_helper(node.right, value)

    def delete(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        if self.root is None:
            return False
        old_size = self.size
        self.root = self._delete_helper(self.root, value)
        return self.size < old_size

    def _delete_helper(self, node: Optional[Node], value: int) -> Optional[Node]:
        if node is None:
            return None

        if value < node.value:
            node.left = self._delete_helper(node.left, value)
            return node
        elif value > node.value:
            node.right = self._delete_helper(node.right, value)
            return node
        else:
            self.size -= 1
            if node.left is None and node.right is None:
                return None
            if node.left is None:
                return node.right
            if node.right is None:
                return node.left
            
            min_node = self._find_min(node.right)
            new_node = Node(min_node.value)
            self.size += 1
            new_node.right = self._delete_helper(node.right, min_node.value)
            new_node.left = node.left
            return new_node

    def _find_min(self, node: Node) -> Node:
        while node.left is not None:
            node = node.left
        return node

    def inorder_traversal(self) -> List[int]:
        result: List[int] = []
        self._inorder_helper(self.root, result)
        return result

    def _inorder_helper(self, node: Optional[Node], result: List[int]) -> None:
        if node is None:
            return
        self._inorder_helper(node.left, result)
        result.append(node.value)
        self._inorder_helper(node.right, result)

def main():
    print("Test Case 1: Basic insert and search")
    bst1 = BST()
    bst1.insert(50)
    bst1.insert(30)
    bst1.insert(70)
    print(f"Search 30: {bst1.search(30)}")
    print(f"Search 100: {bst1.search(100)}")
    print(f"Inorder: {bst1.inorder_traversal()}")

    print("\\nTest Case 2: Delete leaf node")
    bst2 = BST()
    bst2.insert(50)
    bst2.insert(30)
    bst2.insert(70)
    bst2.delete(30)
    print(f"After deleting 30: {bst2.inorder_traversal()}")
    print(f"Search 30: {bst2.search(30)}")

    print("\\nTest Case 3: Delete node with one child")
    bst3 = BST()
    bst3.insert(50)
    bst3.insert(30)
    bst3.insert(70)
    bst3.insert(60)
    bst3.delete(70)
    print(f"After deleting 70: {bst3.inorder_traversal()}")

    print("\\nTest Case 4: Delete node with two children")
    bst4 = BST()
    bst4.insert(50)
    bst4.insert(30)
    bst4.insert(70)
    bst4.insert(20)
    bst4.insert(40)
    bst4.insert(60)
    bst4.insert(80)
    bst4.delete(50)
    print(f"After deleting 50: {bst4.inorder_traversal()}")

    print("\\nTest Case 5: Multiple operations")
    bst5 = BST()
    bst5.insert(15)
    bst5.insert(10)
    bst5.insert(20)
    bst5.insert(8)
    bst5.insert(12)
    bst5.insert(25)
    print(f"Initial tree: {bst5.inorder_traversal()}")
    print(f"Search 12: {bst5.search(12)}")
    bst5.delete(20)
    print(f"After deleting 20: {bst5.inorder_traversal()}")
    print(f"Search 20: {bst5.search(20)}")

if __name__ == "__main__":
    main()
