
class Node:
    def __init__(self, value):
        self.data = value
        self.left = None
        self.right = None

class BST:
    def __init__(self):
        self.root = None
    
    def _insert(self, node, value):
        if node is None:
            return Node(value)
        
        if value < node.data:
            node.left = self._insert(node.left, value)
        elif value > node.data:
            node.right = self._insert(node.right, value)
        
        return node
    
    def insert(self, value):
        self.root = self._insert(self.root, value)
    
    def _search(self, node, value):
        if node is None or node.data == value:
            return node
        
        if value < node.data:
            return self._search(node.left, value)
        
        return self._search(node.right, value)
    
    def search(self, value):
        return self._search(self.root, value) is not None
    
    def _find_min(self, node):
        while node.left is not None:
            node = node.left
        return node
    
    def _delete(self, node, value):
        if node is None:
            return None
        
        if value < node.data:
            node.left = self._delete(node.left, value)
        elif value > node.data:
            node.right = self._delete(node.right, value)
        else:
            if node.left is None:
                return node.right
            elif node.right is None:
                return node.left
            
            min_node = self._find_min(node.right)
            node.data = min_node.data
            node.right = self._delete(node.right, min_node.data)
        
        return node
    
    def delete(self, value):
        self.root = self._delete(self.root, value)
    
    def _inorder(self, node, result):
        if node is not None:
            self._inorder(node.left, result)
            result.append(node.data)
            self._inorder(node.right, result)
    
    def inorder(self):
        result = []
        self._inorder(self.root, result)
        return result

if __name__ == "__main__":
    # Test Case 1: Basic insert and search
    print("Test Case 1: Basic insert and search")
    bst1 = BST()
    bst1.insert(50)
    bst1.insert(30)
    bst1.insert(70)
    bst1.insert(20)
    bst1.insert(40)
    print("Inorder:", bst1.inorder())
    print("Search 40:", bst1.search(40))
    print("Search 60:", bst1.search(60))
    print()
    
    # Test Case 2: Delete leaf node
    print("Test Case 2: Delete leaf node")
    bst2 = BST()
    bst2.insert(50)
    bst2.insert(30)
    bst2.insert(70)
    bst2.insert(20)
    print("Before delete:", bst2.inorder())
    bst2.delete(20)
    print("After delete 20:", bst2.inorder())
    print()
    
    # Test Case 3: Delete node with one child
    print("Test Case 3: Delete node with one child")
    bst3 = BST()
    bst3.insert(50)
    bst3.insert(30)
    bst3.insert(70)
    bst3.insert(60)
    print("Before delete:", bst3.inorder())
    bst3.delete(70)
    print("After delete 70:", bst3.inorder())
    print()
    
    # Test Case 4: Delete node with two children
    print("Test Case 4: Delete node with two children")
    bst4 = BST()
    bst4.insert(50)
    bst4.insert(30)
    bst4.insert(70)
    bst4.insert(20)
    bst4.insert(40)
    bst4.insert(60)
    bst4.insert(80)
    print("Before delete:", bst4.inorder())
    bst4.delete(50)
    print("After delete 50:", bst4.inorder())
    print()
    
    # Test Case 5: Multiple operations
    print("Test Case 5: Multiple operations")
    bst5 = BST()
    bst5.insert(15)
    bst5.insert(10)
    bst5.insert(20)
    bst5.insert(8)
    bst5.insert(12)
    bst5.insert(17)
    bst5.insert(25)
    print("Initial tree:", bst5.inorder())
    print("Search 12:", bst5.search(12))
    bst5.delete(15)
    print("After delete 15:", bst5.inorder())
    bst5.insert(18)
    print("After insert 18:", bst5.inorder())
