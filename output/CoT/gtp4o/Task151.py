# Chain-of-Through Steps: Implement BST with secure, clear operations

class BSTNode:
    __slots__ = ("key", "left", "right")
    def __init__(self, key: int):
        self.key = key
        self.left = None
        self.right = None

class BST:
    def __init__(self):
        self.root: BSTNode | None = None

    def insert(self, key: int) -> bool:
        if self.root is None:
            self.root = BSTNode(key)
            return True
        cur = self.root
        parent = None
        while cur is not None:
            parent = cur
            if key < cur.key:
                cur = cur.left
            elif key > cur.key:
                cur = cur.right
            else:
                return False  # duplicate
        if key < parent.key:
            parent.left = BSTNode(key)
        else:
            parent.right = BSTNode(key)
        return True

    def search(self, key: int) -> bool:
        cur = self.root
        while cur is not None:
            if key == cur.key:
                return True
            cur = cur.left if key < cur.key else cur.right
        return False

    def delete(self, key: int) -> bool:
        self.root, deleted = self._delete_rec(self.root, key)
        return deleted

    def _delete_rec(self, node: BSTNode | None, key: int) -> tuple[BSTNode | None, bool]:
        if node is None:
            return None, False
        if key < node.key:
            node.left, deleted = self._delete_rec(node.left, key)
            return node, deleted
        if key > node.key:
            node.right, deleted = self._delete_rec(node.right, key)
            return node, deleted
        # node to delete
        if node.left is None:
            return node.right, True
        if node.right is None:
            return node.left, True
        # two children: inorder successor
        succ_parent = node
        succ = node.right
        while succ.left is not None:
            succ_parent = succ
            succ = succ.left
        node.key = succ.key
        # delete successor
        if succ_parent.left is succ:
            succ_parent.left, _ = self._delete_rec(succ_parent.left, succ.key)
        else:
            succ_parent.right, _ = self._delete_rec(succ_parent.right, succ.key)
        return node, True

    def inorder(self) -> list[int]:
        res: list[int] = []
        def dfs(n: BSTNode | None):
            if n is None:
                return
            dfs(n.left)
            res.append(n.key)
            dfs(n.right)
        dfs(self.root)
        return res

def _print_list(prefix: str, lst: list[int]) -> None:
    print(f"{prefix}{lst}")

if __name__ == "__main__":
    # Test case 1: Insert and inorder
    bst = BST()
    for v in [50, 30, 20, 40, 70, 60, 80]:
        bst.insert(v)
    _print_list("Inorder after inserts: ", bst.inorder())

    # Test case 2: Search existing
    print("Search 40:", bst.search(40))

    # Test case 3: Search non-existing
    print("Search 25:", bst.search(25))

    # Test case 4: Delete leaf (20)
    print("Delete 20:", bst.delete(20))
    _print_list("Inorder after deleting 20: ", bst.inorder())

    # Test case 5: Delete node with one child (30) and two children (50)
    print("Delete 30:", bst.delete(30))
    print("Delete 50:", bst.delete(50))
    _print_list("Inorder after deleting 30 and 50: ", bst.inorder())