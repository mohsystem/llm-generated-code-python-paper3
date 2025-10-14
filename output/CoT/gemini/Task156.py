class Node:
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None

def preorder_traversal(node):
    """Performs preorder traversal (Root -> Left -> Right) and returns a list."""
    res = []
    if node:
        res.append(node.data)
        res.extend(preorder_traversal(node.left))
        res.extend(preorder_traversal(node.right))
    return res

def inorder_traversal(node):
    """Performs inorder traversal (Left -> Root -> Right) and returns a list."""
    res = []
    if node:
        res.extend(inorder_traversal(node.left))
        res.append(node.data)
        res.extend(inorder_traversal(node.right))
    return res

def postorder_traversal(node):
    """Performs postorder traversal (Left -> Right -> Root) and returns a list."""
    res = []
    if node:
        res.extend(postorder_traversal(node.left))
        res.extend(postorder_traversal(node.right))
        res.append(node.data)
    return res

# Main execution block with test cases
if __name__ == "__main__":
    # --- Test Case 1: A standard binary tree ---
    print("--- Test Case 1: Standard Tree ---")
    root1 = Node(4)
    root1.left = Node(2)
    root1.right = Node(5)
    root1.left.left = Node(1)
    root1.left.right = Node(3)
    
    print("Preorder: ", ' '.join(map(str, preorder_traversal(root1))))
    print("Inorder:  ", ' '.join(map(str, inorder_traversal(root1))))
    print("Postorder:", ' '.join(map(str, postorder_traversal(root1))))
    print()

    # --- Test Case 2: A right-skewed tree ---
    print("--- Test Case 2: Right-Skewed Tree ---")
    root2 = Node(1)
    root2.right = Node(2)
    root2.right.right = Node(3)
    
    print("Preorder: ", ' '.join(map(str, preorder_traversal(root2))))
    print("Inorder:  ", ' '.join(map(str, inorder_traversal(root2))))
    print("Postorder:", ' '.join(map(str, postorder_traversal(root2))))
    print()

    # --- Test Case 3: A left-skewed tree ---
    print("--- Test Case 3: Left-Skewed Tree ---")
    root3 = Node(3)
    root3.left = Node(2)
    root3.left.left = Node(1)
    
    print("Preorder: ", ' '.join(map(str, preorder_traversal(root3))))
    print("Inorder:  ", ' '.join(map(str, inorder_traversal(root3))))
    print("Postorder:", ' '.join(map(str, postorder_traversal(root3))))
    print()

    # --- Test Case 4: A tree with only a root node ---
    print("--- Test Case 4: Single Node Tree ---")
    root4 = Node(10)
    
    print("Preorder: ", ' '.join(map(str, preorder_traversal(root4))))
    print("Inorder:  ", ' '.join(map(str, inorder_traversal(root4))))
    print("Postorder:", ' '.join(map(str, postorder_traversal(root4))))
    print()

    # --- Test Case 5: An empty tree (None root) ---
    print("--- Test Case 5: Empty Tree ---")
    root5 = None
    
    print("Preorder: ", ' '.join(map(str, preorder_traversal(root5))))
    print("Inorder:  ", ' '.join(map(str, inorder_traversal(root5))))
    print("Postorder:", ' '.join(map(str, postorder_traversal(root5))))
    print()