class Node:
    """A node in a binary search tree."""
    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None

def insert(root, key):
    """A recursive function to insert a new key in BST."""
    if root is None:
        return Node(key)
    
    if key < root.key:
        root.left = insert(root.left, key)
    elif key > root.key:
        root.right = insert(root.right, key)
        
    return root

def search(root, key):
    """A recursive function to search for a key in BST."""
    if root is None or root.key == key:
        return root is not None
    
    if key < root.key:
        return search(root.left, key)
    
    return search(root.right, key)

def minValueNode(node):
    """Helper function to find the inorder successor."""
    current = node
    while current and current.left is not None:
        current = current.left
    return current

def deleteNode(root, key):
    """A recursive function to delete a key from BST."""
    if root is None:
        return root

    if key < root.key:
        root.left = deleteNode(root.left, key)
    elif key > root.key:
        root.right = deleteNode(root.right, key)
    else:
        # Node with only one child or no child
        if root.left is None:
            temp = root.right
            root = None # Can be garbage collected
            return temp
        elif root.right is None:
            temp = root.left
            root = None # Can be garbage collected
            return temp

        # Node with two children: Get the inorder successor
        temp = minValueNode(root.right)
        root.key = temp.key
        root.right = deleteNode(root.right, temp.key)

    return root

def inorder(root):
    """Function to do inorder tree traversal."""
    if root:
        inorder(root.left)
        print(root.key, end=" ")
        inorder(root.right)

if __name__ == '__main__':
    root = None
    
    # --- Test Case 1: Insertion and Search ---
    print("--- Test Case 1: Insertion and Search ---")
    root = insert(root, 50)
    root = insert(root, 30)
    root = insert(root, 20)
    root = insert(root, 40)
    root = insert(root, 70)
    root = insert(root, 60)
    root = insert(root, 80)
    print("Inorder traversal:", end=" ")
    inorder(root)
    print()
    print("Search for 60:", "Found" if search(root, 60) else "Not Found")
    print("Search for 90:", "Found" if search(root, 90) else "Not Found")
    print()

    # --- Test Case 2: Deleting a leaf node (20) ---
    print("--- Test Case 2: Deleting a leaf node (20) ---")
    print("Deleting 20...")
    root = deleteNode(root, 20)
    print("Inorder traversal:", end=" ")
    inorder(root)
    print("\n")
    
    # --- Test Case 3: Deleting a node with one child (30) ---
    print("--- Test Case 3: Deleting a node with one child (30) ---")
    print("Deleting 30...")
    root = deleteNode(root, 30)
    print("Inorder traversal:", end=" ")
    inorder(root)
    print("\n")

    # --- Test Case 4: Deleting a node with two children (50) ---
    print("--- Test Case 4: Deleting a node with two children (50) ---")
    print("Deleting 50 (root)...")
    root = deleteNode(root, 50)
    print("Inorder traversal:", end=" ")
    inorder(root)
    print("\n")

    # --- Test Case 5: Deleting another node and searching for a deleted key ---
    print("--- Test Case 5: Deleting another node and checking ---")
    print("Deleting 70...")
    root = deleteNode(root, 70)
    print("Inorder traversal:", end=" ")
    inorder(root)
    print()
    print("Search for 50:", "Found" if search(root, 50) else "Not Found")