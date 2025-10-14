from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class DFSResult:
    ok: bool
    order: List[int]
    error: str


def dfs_traversal(n: int, adj: List[List[int]], start: int) -> DFSResult:
    # Validate inputs
    if not isinstance(n, int) or n <= 0:
        return DFSResult(False, [], "Invalid number of nodes (must be > 0).")
    if not isinstance(adj, list) or len(adj) != n:
        return DFSResult(False, [], "Adjacency list is not a list or size does not match node count.")
    if not isinstance(start, int) or start < 0 or start >= n:
        return DFSResult(False, [], "Start node is out of range.")
    for i, neighbors in enumerate(adj):
        if not isinstance(neighbors, list):
            return DFSResult(False, [], f"Adjacency list contains a non-list entry at node {i}.")
        for v in neighbors:
            if not isinstance(v, int) or v < 0 or v >= n:
                return DFSResult(False, [], f"Edge from {i} to out-of-range node {v}.")

    visited = [False] * n
    order: List[int] = []
    stack: List[int] = [start]

    while stack:
        u = stack.pop()
        if visited[u]:
            continue
        visited[u] = True
        order.append(u)
        # Push neighbors in reverse order for predictability on ordered inputs
        for v in reversed(adj[u]):
            if not visited[v]:
                stack.append(v)

    return DFSResult(True, order, "")


def _build_adj(n: int, edges: List[Tuple[int, int]], undirected: bool) -> List[List[int]]:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if 0 <= u < n and 0 <= v < n:
            adj[u].append(v)
            if undirected:
                adj[v].append(u)
    return adj


if __name__ == "__main__":
    # Test 1: Undirected chain 0-1-2-3, start=0
    n1 = 4
    edges1 = [(0, 1), (1, 2), (2, 3)]
    adj1 = _build_adj(n1, edges1, True)
    res1 = dfs_traversal(n1, adj1, 0)
    print("Test 1:", res1.order if res1.ok else f"Error: {res1.error}")

    # Test 2: Directed cycle 0->1->2->0 and 2->3, start=0
    n2 = 4
    edges2 = [(0, 1), (1, 2), (2, 0), (2, 3)]
    adj2 = _build_adj(n2, edges2, False)
    res2 = dfs_traversal(n2, adj2, 0)
    print("Test 2:", res2.order if res2.ok else f"Error: {res2.error}")

    # Test 3: Disconnected graph, start in second component
    n3 = 5
    edges3 = [(0, 1), (1, 0), (2, 3), (3, 2)]
    adj3 = _build_adj(n3, edges3, False)
    res3 = dfs_traversal(n3, adj3, 2)
    print("Test 3:", res3.order if res3.ok else f"Error: {res3.error}")

    # Test 4: Single node graph
    n4 = 1
    adj4 = _build_adj(n4, [], False)
    res4 = dfs_traversal(n4, adj4, 0)
    print("Test 4:", res4.order if res4.ok else f"Error: {res4.error}")

    # Test 5: Invalid start node
    n5 = 3
    edges5 = [(0, 1), (1, 2)]
    adj5 = _build_adj(n5, edges5, False)
    res5 = dfs_traversal(n5, adj5, 5)
    print("Test 5:", res5.order if res5.ok else f"Error: {res5.error}")