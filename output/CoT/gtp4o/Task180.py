# Chain-of-Through process:
# 1) Problem understanding:
#    Re-root an undirected tree at a selected node. Return parent array with parent[new_root] = -1.
# 2) Security requirements:
#    Validate node bounds, edges count equals n-1, node indices in range, no self-loops, connectivity.
# 3) Secure coding generation:
#    Use iterative stack to avoid recursion limits; avoid mutating input; robust error handling.
# 4) Code review:
#    Checks for all invalid inputs and ensures no index errors.
# 5) Secure code output:
#    Raise ValueError on invalid input; caller demonstrates try/except.

from typing import List, Tuple

def reparent_tree(n: int, edges: List[Tuple[int, int]], new_root: int) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if edges is None:
        raise ValueError("edges must not be None")
    if len(edges) != n - 1:
        raise ValueError("edges must contain exactly n-1 edges for a tree")
    if new_root < 0 or new_root >= n:
        raise ValueError("new_root out of bounds")

    adj = [[] for _ in range(n)]
    for i, e in enumerate(edges):
        if e is None or len(e) != 2:
            raise ValueError(f"Invalid edge at index {i}")
        u, v = e
        if not (0 <= u < n and 0 <= v < n):
            raise ValueError(f"Edge node out of bounds at index {i}")
        if u == v:
            raise ValueError(f"Self-loop detected at index {i}")
        adj[u].append(v)
        adj[v].append(u)

    parent = [None] * n
    parent[new_root] = -1
    stack = [new_root]
    while stack:
        u = stack.pop()
        for v in adj[u]:
            if parent[v] is None:
                parent[v] = u
                stack.append(v)

    if any(p is None for p in parent):
        raise ValueError("Input is not a connected tree")

    return parent

def _print_arr(arr: List[int]) -> None:
    print(arr)

if __name__ == "__main__":
    # 5 test cases
    try:
        n1 = 10
        edges1 = [(0,1),(0,2),(0,3),(1,4),(1,5),(2,6),(2,7),(3,8),(3,9)]
        _print_arr(reparent_tree(n1, edges1, 6))
    except Exception as e:
        print("Test 1 error:", e)

    try:
        n2 = 10
        edges2 = [(0,1),(0,2),(0,3),(1,4),(1,5),(2,6),(2,7),(3,8),(3,9)]
        _print_arr(reparent_tree(n2, edges2, 0))
    except Exception as e:
        print("Test 2 error:", e)

    try:
        n3 = 5
        edges3 = [(0,1),(1,2),(2,3),(3,4)]
        _print_arr(reparent_tree(n3, edges3, 4))
    except Exception as e:
        print("Test 3 error:", e)

    try:
        n4 = 6
        edges4 = [(0,1),(0,2),(0,3),(0,4),(0,5)]
        _print_arr(reparent_tree(n4, edges4, 3))
    except Exception as e:
        print("Test 4 error:", e)

    try:
        n5 = 5
        edges5 = [(0,1),(1,2),(1,3),(3,4)]
        _print_arr(reparent_tree(n5, edges5, 4))
    except Exception as e:
        print("Test 5 error:", e)