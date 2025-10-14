class Task151:
    class Node:
        def __init__(self, key):
            self.key = key
            self.left = None
            self.right = None

    def __init__(self):
        self.root = None

    def search(self, key):
        cur = self.root
        while cur:
            if key == cur.key:
                return True
            if key < cur.key:
                cur = cur.left
            else:
                cur = cur.right
        return False

    def insert(self, key):
        if self.search(key):
            return False
        self.root = self._insert_rec(self.root, key)
        return True

    def _insert_rec(self, node, key):
        if not node:
            return self.Node(key)
        if key < node.key:
            node.left = self._insert_rec(node.left, key)
        elif key > node.key:
            node.right = self._insert_rec(node.right, key)
        return node

    def delete(self, key):
        if not self.search(key):
            return False
        self.root = self._delete_rec(self.root, key)
        return True

    def _delete_rec(self, node, key):
        if not node:
            return None
        if key < node.key:
            node.left = self._delete_rec(node.left, key)
        elif key > node.key:
            node.right = self._delete_rec(node.right, key)
        else:
            if not node.left:
                return node.right
            if not node.right:
                return node.left
            succ = node.right
            while succ.left:
                succ = succ.left
            node.key = succ.key
            node.right = self._delete_rec(node.right, succ.key)
        return node

    def inorder(self):
        res = []
        self._inorder_rec(self.root, res)
        return res

    def _inorder_rec(self, node, res):
        if not node:
            return
        self._inorder_rec(node.left, res)
        res.append(node.key)
        self._inorder_rec(node.right, res)


if __name__ == "__main__":
    bst = Task151()
    # Test 1: Insert values and print inorder
    vals = [5, 3, 7, 2, 4, 6, 8]
    print([bst.insert(v) for v in vals])
    print(bst.inorder())

    # Test 2: Search existing value
    print(bst.search(4))

    # Test 3: Search non-existing value
    print(bst.search(10))

    # Test 4: Delete leaf (2) and node with one child (3), then print inorder
    print(bst.delete(2))
    print(bst.delete(3))
    print(bst.inorder())

    # Test 5: Delete node with two children (7), try duplicate insert (5), delete non-existent (42)
    print(bst.delete(7))
    print(bst.insert(5))
    print(bst.delete(42))
    print(bst.inorder())