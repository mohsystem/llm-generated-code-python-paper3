class Node:
    __slots__ = ("key", "left", "right")
    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None

class BST:
    def __init__(self):
        self.root = None

    def insert(self, key: int) -> bool:
        if self.root is None:
            self.root = Node(key)
            return True
        parent = None
        curr = self.root
        while curr is not None:
            parent = curr
            if key == curr.key:
                return False
            if key < curr.key:
                curr = curr.left
            else:
                curr = curr.right
        if key < parent.key:
            parent.left = Node(key)
        else:
            parent.right = Node(key)
        return True

    def search(self, key: int) -> bool:
        curr = self.root
        while curr is not None:
            if key == curr.key:
                return True
            curr = curr.left if key < curr.key else curr.right
        return False

    def delete(self, key: int) -> bool:
        parent = None
        curr = self.root
        while curr is not None and curr.key != key:
            parent = curr
            curr = curr.left if key < curr.key else curr.right
        if curr is None:
            return False

        if curr.left is not None and curr.right is not None:
            succ_parent = curr
            succ = curr.right
            while succ.left is not None:
                succ_parent = succ
                succ = succ.left
            curr.key = succ.key
            parent = succ_parent
            curr = succ

        child = curr.left if curr.left is not None else curr.right
        if parent is None:
            self.root = child
        elif parent.left is curr:
            parent.left = child
        else:
            parent.right = child
        return True

    def inorder(self):
        res = []
        stack = []
        curr = self.root
        while curr is not None or stack:
            while curr is not None:
                stack.append(curr)
                curr = curr.left
            curr = stack.pop()
            res.append(curr.key)
            curr = curr.right
        return res

if __name__ == "__main__":
    tree = BST()
    initial = [5, 3, 7, 2, 4, 6, 8]
    for x in initial:
        tree.insert(x)

    print("Search 4 (expect True):", tree.search(4))
    print("Search 10 (expect False):", tree.search(10))

    tree.delete(2)  # leaf
    print("After deleting 2 (leaf):", tree.inorder())

    tree.delete(3)  # one child
    print("After deleting 3 (one child):", tree.inorder())

    tree.delete(5)  # two children
    print("After deleting 5 (two children):", tree.inorder())