
class Node:
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None

class Task151:
    def __init__(self):
        self.root = None
    
    def insert(self, data):
        if not isinstance(data, int):
            raise ValueError("Data must be an integer")
        self.root = self._insert_rec(self.root, data)
    
    def _insert_rec(self, root, data):
        if root is None:
            return Node(data)
        
        if data < root.data:
            root.left = self._insert_rec(root.left, data)
        elif data > root.data:
            root.right = self._insert_rec(root.right, data)
        
        return root
    
    def search(self, data):
        if not isinstance(data, int):
            raise ValueError("Data must be an integer")
        return self._search_rec(self.root, data)
    
    def _search_rec(self, root, data):
        if root is None:
            return False
        
        if root.data == data:
            return True
        
        if data < root.data:
            return self._search_rec(root.left, data)
        else:
            return self._search_rec(root.right, data)
    
    def delete(self, data):
        if not isinstance(data, int):
            raise ValueError("Data must be an integer")
        self.root = self._delete_rec(self.root, data)
    
    def _delete_rec(self, root, data):
        if root is None:
            return None
        
        if data < root.data:
            root.left = self._delete_rec(root.left, data)
        elif data > root.data:
            root.right = self._delete_rec(root.right, data)
        else:
            if root.left is None:
                return root.right
            elif root.right is None:
                return root.left
            
            root.data = self._min_value(root.right)
            root.right = self._delete_rec(root.right, root.data)
        
        return root
    
    def _min_value(self, root):
        min_value = root.data
        while root.left is not None:
            min_value = root.left.data
            root = root.left
        return min_value
    
    def inorder(self):
        result = []
        self._inorder_rec(self.root, result)
        return result
    
    def _inorder_rec(self, root, result):
        if root is not None:
            self._inorder_rec(root.left, result)
            result.append(root.data)
            self._inorder_rec(root.right, result)

if __name__ == "__main__":
    # Test Case 1: Basic insertion and search
    print("Test Case 1: Basic insertion and search")
    bst1 = Task151()
    bst1.insert(50)
    bst1.insert(30)
    bst1.insert(70)
    bst1.insert(20)
    bst1.insert(40)
    print(f"Inorder traversal: {bst1.inorder()}")
    print(f"Search 40: {bst1.search(40)}")
    print(f"Search 60: {bst1.search(60)}")
    print()
    
    # Test Case 2: Delete leaf node
    print("Test Case 2: Delete leaf node")
    bst2 = Task151()
    bst2.insert(50)
    bst2.insert(30)
    bst2.insert(70)
    bst2.insert(20)
    print(f"Before delete: {bst2.inorder()}")
    bst2.delete(20)
    print(f"After delete 20: {bst2.inorder()}")
    print()
    
    # Test Case 3: Delete node with one child
    print("Test Case 3: Delete node with one child")
    bst3 = Task151()
    bst3.insert(50)
    bst3.insert(30)
    bst3.insert(70)
    bst3.insert(60)
    print(f"Before delete: {bst3.inorder()}")
    bst3.delete(70)
    print(f"After delete 70: {bst3.inorder()}")
    print()
    
    # Test Case 4: Delete node with two children
    print("Test Case 4: Delete node with two children")
    bst4 = Task151()
    bst4.insert(50)
    bst4.insert(30)
    bst4.insert(70)
    bst4.insert(20)
    bst4.insert(40)
    bst4.insert(60)
    bst4.insert(80)
    print(f"Before delete: {bst4.inorder()}")
    bst4.delete(50)
    print(f"After delete 50: {bst4.inorder()}")
    print()
    
    # Test Case 5: Empty tree operations
    print("Test Case 5: Empty tree operations")
    bst5 = Task151()
    print(f"Search in empty tree: {bst5.search(10)}")
    bst5.delete(10)
    print(f"Inorder of empty tree: {bst5.inorder()}")
