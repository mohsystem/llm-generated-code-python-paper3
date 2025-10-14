from collections import deque
from typing import List, Tuple, Optional

def reparent_tree(n: int, edges: List[Tuple[int, int]], root: int) -> List[List[int]]:
    if n < 1:
        raise ValueError("Number of nodes must be >= 1")
    if root < 0 or root >= n:
        raise ValueError("Root out of range")
    if edges is None:
        raise ValueError("Edges cannot be None")
    if len(edges) != n - 1:
        raise ValueError("Edges must be n-1 for a valid tree")

    # Validate edges and check duplicates/self-loops
    seen = set()
    adj = [[] for _ in range(n)]
    for idx, (u, v) in enumerate(edges):
        if not (0 <= u < n and 0 <= v < n):
            raise ValueError("Edge node out of range")
        if u == v:
            raise ValueError("Self-loop detected")
        a, b = (u, v) if u < v else (v, u)
        if (a, b) in seen:
            raise ValueError("Duplicate edge detected")
        seen.add((a, b))
        adj[u].append(v)
        adj[v].append(u)

    parent = [-1] * n
    parent[root] = root
    q = deque([root])
    children = [[] for _ in range(n)]
    visited = 0

    while q:
        u = q.popleft()
        visited += 1
        for v in adj[u]:
            if v != parent[u]:
                parent[v] = u
                children[u].append(v)
                q.append(v)

    if visited != n:
        raise ValueError("Graph is not connected")

    return children

def print_children(children: Optional[List[List[int]]]) -> None:
    if children is None:
        print("None")
        return
    for i, lst in enumerate(children):
        print(f"{i}: [{', '.join(map(str, lst))}]")

if __name__ == "__main__":
    # Test 1: Example tree reparented at 6
    n1 = 10
    e1 = [(0,1),(0,2),(0,3),(1,4),(1,5),(2,6),(2,7),(3,8),(3,9)]
    root1 = 6
    print("Test 1:")
    try:
        r1 = reparent_tree(n1, e1, root1)
        print_children(r1)
    except Exception as ex:
        print(f"Error: {ex}")

    # Test 2: Chain 0-1-2-3 reparented at 3
    n2 = 4
    e2 = [(0,1),(1,2),(2,3)]
    root2 = 3
    print("Test 2:")
    try:
        r2 = reparent_tree(n2, e2, root2)
        print_children(r2)
    except Exception as ex:
        print(f"Error: {ex}")

    # Test 3: Single node
    n3 = 1
    e3 = []
    root3 = 0
    print("Test 3:")
    try:
        r3 = reparent_tree(n3, e3, root3)
        print_children(r3)
    except Exception as ex:
        print(f"Error: {ex}")

    # Test 4: Star centered at 0 reparented at 3
    n4 = 5
    e4 = [(0,1),(0,2),(0,3),(0,4)]
    root4 = 3
    print("Test 4:")
    try:
        r4 = reparent_tree(n4, e4, root4)
        print_children(r4)
    except Exception as ex:
        print(f"Error: {ex}")

    # Test 5: Invalid (wrong number of edges)
    n5 = 3
    e5 = [(0,1)]
    root5 = 0
    print("Test 5:")
    try:
        r5 = reparent_tree(n5, e5, root5)
        print_children(r5)
    except Exception as ex:
        print(f"Error: {ex}")