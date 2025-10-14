from __future__ import annotations
from typing import List, Optional

class Node:
    def __init__(self, value: int) -> None:
        self.value: int = value
        self.children: List[Node] = []
        self.parent: Optional[Node] = None  # used only during building

    def add_child(self, child: Optional["Node"]) -> None:
        if child is None:
            return
        self.children.append(child)

    def __str__(self) -> str:
        return self.to_string()

    def to_string(self) -> str:
        parts: List[str] = []
        self._to_string(self, parts)
        return "".join(parts)

    @staticmethod
    def _to_string(node: "Node", parts: List[str]) -> None:
        parts.append(str(node.value))
        if node.children:
            parts.append("(")
            for i, c in enumerate(node.children):
                if i > 0:
                    parts.append(",")
                Node._to_string(c, parts)
            parts.append(")")

def assign_parents(root: Node, parent: Optional[Node]) -> None:
    root.parent = parent
    for c in root.children:
        assign_parents(c, root)

def find(root: Node, target: int) -> Optional[Node]:
    if root.value == target:
        return root
    for c in root.children:
        f = find(c, target)
        if f is not None:
            return f
    return None

def build_reoriented(node: Node, prev: Optional[Node]) -> Node:
    new_node = Node(node.value)
    for c in node.children:
        if c is not prev:
            new_node.add_child(build_reoriented(c, node))
    if node.parent is not None and node.parent is not prev:
        new_node.add_child(build_reoriented(node.parent, node))
    return new_node

def reparent(root: Optional[Node], target_value: int) -> Optional[Node]:
    if root is None:
        return None
    assign_parents(root, None)
    target = find(root, target_value)
    if target is None:
        return None
    return build_reoriented(target, None)

def build_example_tree() -> Node:
    #        0
    #      / | \
    #     1  2  3
    #    / \ / \ / \
    #   4  5 6  7 8  9
    n0 = Node(0)
    n1 = Node(1); n2 = Node(2); n3 = Node(3)
    n4 = Node(4); n5 = Node(5)
    n6 = Node(6); n7 = Node(7)
    n8 = Node(8); n9 = Node(9)
    n0.add_child(n1); n0.add_child(n2); n0.add_child(n3)
    n1.add_child(n4); n1.add_child(n5)
    n2.add_child(n6); n2.add_child(n7)
    n3.add_child(n8); n3.add_child(n9)
    return n0

def build_single_node(value: int) -> Node:
    return Node(value)

if __name__ == "__main__":
    # Test 1: Reparent on 6
    root = build_example_tree()
    r1 = reparent(root, 6)
    print(r1.to_string() if r1 else "null")

    # Test 2: Reparent on 0
    r2 = reparent(root, 0)
    print(r2.to_string() if r2 else "null")

    # Test 3: Reparent on 9
    r3 = reparent(root, 9)
    print(r3.to_string() if r3 else "null")

    # Test 4: Single node tree
    single = build_single_node(42)
    r4 = reparent(single, 42)
    print(r4.to_string() if r4 else "null")

    # Test 5: Target not found
    r5 = reparent(root, 100)
    print(r5.to_string() if r5 else "null")