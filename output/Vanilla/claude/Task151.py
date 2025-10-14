
class Node:
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None

class BinarySearchTree:
    def __init__(self):
        self.root = None
    
    def insert(self, data, root=None):
        if root is None:
            if self.root is None:
                self.root = Node(data)
                return self.root
            root = self.root
        
        if data < root.data:
            if root.left is None:
                root.left = Node(data)
            else:
                self.insert(data, root.left)
        elif data > root.data:
            if root.right is None:
                root.right = Node(data)
            else:
                self.insert(data, root.right)
        
        return root
    
    def search(self, data, root=None):
        if root is None:
            root = self.root
        
        if root is None:
            return False
        
        if root.data == data:
            return True
        
        if data < root.data:
            return self.search(data, root.left)
        else:
            return self.search(data, root.right)
    
    def delete(self, data, root=None):
        if root is None:
            self.root = self._delete_helper(self.root, data)
            return
        
        return self._delete_helper(root, data)
    
    def _delete_helper(self, root, data):
        if root is None:
            return None
        
        if data < root.data:
            root.left = self._delete_helper(root.left, data)
        elif data > root.data:
            root.right = self._delete_helper(root.right, data)
        else:
            # Node to be deleted found
            
            # Case 1: No child or one child
            if root.left is None:
                return root.right
            elif root.right is None:
                return root.left
            
            # Case 2: Two children
            # Find inorder successor (smallest in right subtree)
            successor = self._find_min(root.right)
            root.data = successor.data
            root.right = self._delete_helper(root.right, successor.data)
        
        return root
    
    def _find_min(self, root):
        while root.left is not None:
            root = root.left
        return root
    
    def inorder(self, root=None):
        if root is None:
            root = self.root
        
        result = []
        self._inorder_helper(root, result)
        return result
    
    def _inorder_helper(self, root, result):
        if root is not None:
            self._inorder_helper(root.left, result)
            result.append(root.data)
            self._inorder_helper(root.right, result)

def main():
    # Test Case 1: Basic insert and search
    print("Test Case 1: Basic insert and search")
    bst1 = BinarySearchTree()
    bst1.insert(50)
    bst1.insert(30)
    bst1.insert(70)
    bst1.insert(20)
    bst1.insert(40)
    print(f"Search 40: {bst1.search(40)}")
    print(f"Search 60: {bst1.search(60)}")
    print(f"Inorder: {bst1.inorder()}")
    print()
    
    # Test Case 2: Delete leaf node
    print("Test Case 2: Delete leaf node")
    bst2 = BinarySearchTree()
    bst2.insert(50)
    bst2.insert(30)
    bst2.insert(70)
    bst2.insert(20)
    bst2.insert(40)
    bst2.delete(20)
    print(f"After deleting 20: {bst2.inorder()}")
    print(f"Search 20: {bst2.search(20)}")
    print()
    
    # Test Case 3: Delete node with one child
    print("Test Case 3: Delete node with one child")
    bst3 = BinarySearchTree()
    bst3.insert(50)
    bst3.insert(30)
    bst3.insert(70)
    bst3.insert(60)
    bst3.delete(70)
    print(f"After deleting 70: {bst3.inorder()}")
    print()
    
    # Test Case 4: Delete node with two children
    print("Test Case 4: Delete node with two children")
    bst4 = BinarySearchTree()
    bst4.insert(50)
    bst4.insert(30)
    bst4.insert(70)
    bst4.insert(20)
    bst4.insert(40)
    bst4.insert(60)
    bst4.insert(80)
    bst4.delete(50)
    print(f"After deleting 50: {bst4.inorder()}")
    print()
    
    # Test Case 5: Complex operations
    print("Test Case 5: Complex operations")
    bst5 = BinarySearchTree()
    values = [15, 10, 20, 8, 12, 17, 25]
    for val in values:
        bst5.insert(val)
    print(f"Initial tree: {bst5.inorder()}")
    print(f"Search 12: {bst5.search(12)}")
    bst5.delete(15)
    print(f"After deleting 15: {bst5.inorder()}")
    bst5.insert(14)
    print(f"After inserting 14: {bst5.inorder()}")

if __name__ == "__main__":
    main()
