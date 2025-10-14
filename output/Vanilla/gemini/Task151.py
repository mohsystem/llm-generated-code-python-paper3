class Node:
    """A node in a Binary Search Tree."""
    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None

class BST:
    """Binary Search Tree implementation."""
    def __init__(self):
        self.root = None

    def search(self, key):
        """Public method to search for a key."""
        return self._search_rec(self.root, key) is not None

    def _search_rec(self, node, key):
        """Recursive helper for search."""
        if node is None or node.key == key:
            return node
        if key < node.key:
            return self._search_rec(node.left, key)
        return self._search_rec(node.right, key)

    def insert(self, key):
        """Public method to insert a key."""
        self.root = self._insert_rec(self.root, key)

    def _insert_rec(self, node, key):
        """Recursive helper for insert."""
        if node is None:
            return Node(key)
        if key < node.key:
            node.left = self._insert_rec(node.left, key)
        elif key > node.key:
            node.right = self._insert_rec(node.right, key)
        return node

    def delete(self, key):
        """Public method to delete a key."""
        self.root = self._delete_rec(self.root, key)

    def _delete_rec(self, node, key):
        """Recursive helper for delete."""
        if node is None:
            return node

        if key < node.key:
            node.left = self._delete_rec(node.left, key)
        elif key > node.key:
            node.right = self._delete_rec(node.right, key)
        else:
            # Node with only one child or no child
            if node.left is None:
                return node.right
            elif node.right is None:
                return node.left

            # Node with two children
            temp = self._min_value_node(node.right)
            node.key = temp.key
            node.right = self._delete_rec(node.right, temp.key)
        return node

    def _min_value_node(self, node):
        """Find the inorder successor."""
        current = node
        while current.left is not None:
            current = current.left
        return current

    def inorder(self):
        """Public method for inorder traversal."""
        self._inorder_rec(self.root)
        print()

    def _inorder_rec(self, node):
        """Recursive helper for inorder traversal."""
        if node:
            self._inorder_rec(node.left)
            print(node.key, end=" ")
            self._inorder_rec(node.right)


if __name__ == "__main__":
    bst = BST()

    # Test Case 1: Insertion
    print("--- Test Case 1: Insertion ---")
    keys_to_insert = [50, 30, 20, 40, 70, 60, 80]
    for key in keys_to_insert:
        bst.insert(key)
    print("Inorder traversal of the initial BST: ", end="")
    bst.inorder()

    # Test Case 2: Search
    print("\n--- Test Case 2: Search ---")
    print(f"Search for 60: {'Found' if bst.search(60) else 'Not Found'}")
    print(f"Search for 90: {'Found' if bst.search(90) else 'Not Found'}")

    # Test Case 3: Delete a leaf node
    print("\n--- Test Case 3: Delete a leaf node (20) ---")
    bst.delete(20)
    print("Inorder traversal after deleting 20: ", end="")
    bst.inorder()

    # Test Case 4: Delete a node with one child
    print("\n--- Test Case 4: Delete a node with one child (30) ---")
    bst.delete(30)
    print("Inorder traversal after deleting 30: ", end="")
    bst.inorder()

    # Test Case 5: Delete a node with two children
    print("\n--- Test Case 5: Delete a node with two children (50) ---")
    bst.delete(50)
    print("Inorder traversal after deleting 50: ", end="")
    bst.inorder()