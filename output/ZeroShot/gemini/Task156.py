class Node:
    """Node class for the binary tree"""
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None

def preorder_traversal(node):
    """
    Performs a preorder traversal of the binary tree.
    Root -> Left -> Right
    :param node: The root node of the tree/subtree.
    """
    if node is None:
        return
    print(node.data, end=" ")
    preorder_traversal(node.left)
    preorder_traversal(node.right)

def inorder_traversal(node):
    """
    Performs an inorder traversal of the binary tree.
    Left -> Root -> Right
    :param node: The root node of the tree/subtree.
    """
    if node is None:
        return
    inorder_traversal(node.left)
    print(node.data, end=" ")
    inorder_traversal(node.right)

def postorder_traversal(node):
    """
    Performs a postorder traversal of the binary tree.
    Left -> Right -> Root
    :param node: The root node of the tree/subtree.
    """
    if node is None:
        return
    postorder_traversal(node.left)
    postorder_traversal(node.right)
    print(node.data, end=" ")

def main():
    # Test Case 1: A complete binary tree
    print("--- Test Case 1: Complete Binary Tree ---")
    root1 = Node(1)
    root1.left = Node(2)
    root1.right = Node(3)
    root1.left.left = Node(4)
    root1.left.right = Node(5)
    root1.right.left = Node(6)
    root1.right.right = Node(7)
    
    print("Preorder:  ", end="")
    preorder_traversal(root1)
    print()
    print("Inorder:   ", end="")
    inorder_traversal(root1)
    print()
    print("Postorder: ", end="")
    postorder_traversal(root1)
    print("\n")

    # Test Case 2: A right-skewed tree
    print("--- Test Case 2: Right-Skewed Tree ---")
    root2 = Node(10)
    root2.right = Node(20)
    root2.right.right = Node(30)
    root2.right.right.right = Node(40)

    print("Preorder:  ", end="")
    preorder_traversal(root2)
    print()
    print("Inorder:   ", end="")
    inorder_traversal(root2)
    print()
    print("Postorder: ", end="")
    postorder_traversal(root2)
    print("\n")

    # Test Case 3: A left-skewed tree
    print("--- Test Case 3: Left-Skewed Tree ---")
    root3 = Node(50)
    root3.left = Node(40)
    root3.left.left = Node(30)
    root3.left.left.left = Node(20)

    print("Preorder:  ", end="")
    preorder_traversal(root3)
    print()
    print("Inorder:   ", end="")
    inorder_traversal(root3)
    print()
    print("Postorder: ", end="")
    postorder_traversal(root3)
    print("\n")
    
    # Test Case 4: An empty tree (None root)
    print("--- Test Case 4: Empty Tree ---")
    root4 = None
    
    print("Preorder:  ", end="")
    preorder_traversal(root4)
    print("(empty)")
    print("Inorder:   ", end="")
    inorder_traversal(root4)
    print("(empty)")
    print("Postorder: ", end="")
    postorder_traversal(root4)
    print("(empty)\n")

    # Test Case 5: A tree with only one node
    print("--- Test Case 5: Single Node Tree ---")
    root5 = Node(100)

    print("Preorder:  ", end="")
    preorder_traversal(root5)
    print()
    print("Inorder:   ", end="")
    inorder_traversal(root5)
    print()
    print("Postorder: ", end="")
    postorder_traversal(root5)
    print("\n")

if __name__ == "__main__":
    main()