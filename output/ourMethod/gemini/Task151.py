from typing import Optional

class Node:
    """A node in a binary search tree."""
    def __init__(self, key: int):
        self.key: int = key
        self.left: Optional[Node] = None
        self.right: Optional[Node] = None

class BinarySearchTree:
    """A class for a binary search tree."""
    def __init__(self):
        self.root: Optional[Node] = None

    def insert(self, key: int) -> None:
        """Public method to insert a key into the BST."""
        self.root = self._insert_rec(self.root, key)

    def _insert_rec(self, node: Optional[Node], key: int) -> Node:
        """Recursive helper to insert a key."""
        if node is None:
            return Node(key)
        if key < node.key:
            node.left = self._insert_rec(node.left, key)
        elif key > node.key:
            node.right = self._insert_rec(node.right, key)
        return node

    def search(self, key: int) -> bool:
        """Public method to search for a key in the BST."""
        return self._search_rec(self.root, key)

    def _search_rec(self, node: Optional[Node], key: int) -> bool:
        """Recursive helper to search for a key."""
        if node is None:
            return False
        if node.key == key:
            return True
        if key < node.key:
            return self._search_rec(node.left, key)
        return self._search_rec(node.right, key)

    def delete(self, key: int) -> None:
        """Public method to delete a key from the BST."""
        self.root = self._delete_rec(self.root, key)

    def _delete_rec(self, node: Optional[Node], key: int) -> Optional[Node]:
        """Recursive helper to delete a key."""
        if node is None:
            return node

        if key < node.key:
            node.left = self._delete_rec(node.left, key)
        elif key > node.key:
            node.right = self._delete_rec(node.right, key)
        else:
            # Case 1 or 2: Node with one or no child
            if node.left is None:
                return node.right
            elif node.right is None:
                return node.left
            
            # Case 3: Node with two children
            temp = self._min_value_node(node.right)
            node.key = temp.key
            node.right = self._delete_rec(node.right, temp.key)
        return node

    def _min_value_node(self, node: Node) -> Node:
        """Helper to find the node with the minimum value in a subtree."""
        current = node
        while current.left is not None:
            current = current.left
        return current

def main():
    """Main function with test cases."""
    bst = BinarySearchTree()

    # Test Case 1: Insert and search
    print("Test Case 1: Insert and Search")
    bst.insert(50)
    bst.insert(30)
    bst.insert(70)
    print(f"Search for 30: {bst.search(30)}")
    print(f"Search for 100: {bst.search(100)}")
    print("---")

    # Test Case 2: Delete a leaf node
    print("Test Case 2: Delete a leaf node")
    bst.insert(20)
    print(f"Search for 20 before delete: {bst.search(20)}")
    bst.delete(20)
    print(f"Search for 20 after delete: {bst.search(20)}")
    print("---")

    # Test Case 3: Delete a node with one child
    print("Test Case 3: Delete a node with one child")
    bst.insert(40)
    print(f"Search for 30 before delete: {bst.search(30)}")
    print(f"Search for 40 before delete: {bst.search(40)}")
    bst.delete(30)
    print(f"Search for 30 after delete: {bst.search(30)}")
    print(f"Search for 40 after delete: {bst.search(40)}")
    print("---")

    # Test Case 4: Delete a node with two children
    print("Test Case 4: Delete a node with two children")
    bst.insert(60)
    bst.insert(80)
    print(f"Search for 70 before delete: {bst.search(70)}")
    bst.delete(70)
    print(f"Search for 70 after delete: {bst.search(70)}")
    print(f"Search for 80 (new subtree root): {bst.search(80)}")
    print("---")

    # Test Case 5: Delete root node
    print("Test Case 5: Delete root node")
    print(f"Search for 50 before delete: {bst.search(50)}")
    bst.delete(50)
    print(f"Search for 50 after delete: {bst.search(50)}")
    print(f"Search for 60 (new root): {bst.search(60)}")
    print("---")

if __name__ == "__main__":
    main()