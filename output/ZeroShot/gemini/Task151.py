class Node:
    """A node in a binary search tree."""
    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None

class BinarySearchTree:
    """A class for a binary search tree."""
    def __init__(self):
        self.root = None

    def insert(self, key):
        """Public method to insert a key."""
        self.root = self._insert_rec(self.root, key)

    def _insert_rec(self, node, key):
        """Recursive helper to insert a key."""
        if node is None:
            return Node(key)
        if key < node.key:
            node.left = self._insert_rec(node.left, key)
        elif key > node.key:
            node.right = self._insert_rec(node.right, key)
        return node

    def search(self, key):
        """Public method to search for a key."""
        return self._search_rec(self.root, key) is not None

    def _search_rec(self, node, key):
        """Recursive helper to search for a key."""
        if node is None or node.key == key:
            return node
        if key < node.key:
            return self._search_rec(node.left, key)
        return self._search_rec(node.right, key)

    def delete(self, key):
        """Public method to delete a key."""
        self.root = self._delete_rec(self.root, key)

    def _delete_rec(self, node, key):
        """Recursive helper to delete a key."""
        if node is None:
            return node

        if key < node.key:
            node.left = self._delete_rec(node.left, key)
        elif key > node.key:
            node.right = self._delete_rec(node.right, key)
        else:
            # Case 1 & 2: Node with only one child or no child
            if node.left is None:
                return node.right
            elif node.right is None:
                return node.left

            # Case 3: Node with two children
            # Get the inorder successor (smallest in the right subtree)
            temp = self._min_value_node(node.right)
            node.key = temp.key
            # Delete the inorder successor
            node.right = self._delete_rec(node.right, temp.key)
        return node

    def _min_value_node(self, node):
        """Helper to find the node with the minimum key value in a subtree."""
        current = node
        while current.left is not None:
            current = current.left
        return current
        
    def inorder(self):
        """Helper method to print inorder traversal."""
        self._inorder_rec(self.root)
        print()
    
    def _inorder_rec(self, node):
        if node:
            self._inorder_rec(node.left)
            print(node.key, end=' ')
            self._inorder_rec(node.right)


if __name__ == "__main__":
    tree = BinarySearchTree()
    
    #        50
    #       /  \
    #      30   70
    #     / \   / \
    #    20 40 60  80
    tree.insert(50)
    tree.insert(30)
    tree.insert(20)
    tree.insert(40)
    tree.insert(70)
    tree.insert(60)
    tree.insert(80)
    
    print("Initial tree (inorder):")
    tree.inorder()

    # Test Case 1: Search for an element that exists
    print("Test Case 1: Search for 40")
    print(f"Found 40: {tree.search(40)}")

    # Test Case 2: Search for an element that does not exist
    print("\nTest Case 2: Search for 90")
    print(f"Found 90: {tree.search(90)}")
    
    # Test Case 3: Delete a leaf node (20)
    print("\nTest Case 3: Delete 20 (leaf node)")
    tree.delete(20)
    print("Tree after deleting 20: ", end="")
    tree.inorder()

    # Test Case 4: Delete a node with one child (30)
    print("\nTest Case 4: Delete 30 (node with one child)")
    tree.delete(30)
    print("Tree after deleting 30: ", end="")
    tree.inorder()
    
    # Test Case 5: Delete a node with two children (50 - the root)
    print("\nTest Case 5: Delete 50 (node with two children - root)")
    tree.delete(50)
    print("Tree after deleting 50: ", end="")
    tree.inorder()