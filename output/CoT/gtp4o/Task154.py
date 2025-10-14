from typing import List, Tuple

def dfs(n: int, edges: List[Tuple[int, int]], start: int, directed: bool = False) -> List[int]:
    if n <= 0:
        raise ValueError("Number of nodes must be positive.")
    if start < 0 or start >= n:
        raise ValueError("Start node out of range.")
    if edges is None:
        edges = []

    adj: List[List[int]] = [[] for _ in range(n)]
    for idx, (u, v) in enumerate(edges):
        if not (0 <= u < n and 0 <= v < n):
            raise ValueError(f"Edge vertex out of range at index {idx}")
        adj[u].append(v)
        if not directed:
            adj[v].append(u)

    for i in range(n):
        adj[i].sort()

    visited = [False] * n
    result: List[int] = []
    stack: List[int] = [start]

    while stack:
        u = stack.pop()
        if visited[u]:
            continue
        visited[u] = True
        result.append(u)
        for v in reversed(adj[u]):
            if not visited[v]:
                stack.append(v)
    return result

if __name__ == "__main__":
    # Test case 1: Simple chain undirected
    n1 = 4
    edges1 = [(0,1), (1,2), (2,3)]
    print("Test 1:", dfs(n1, edges1, 0, directed=False))

    # Test case 2: Branching undirected
    n2 = 5
    edges2 = [(0,1), (0,2), (1,3), (1,4)]
    print("Test 2:", dfs(n2, edges2, 0, directed=False))

    # Test case 3: Directed with cycle
    n3 = 4
    edges3 = [(0,1), (1,2), (2,0), (2,3)]
    print("Test 3:", dfs(n3, edges3, 0, directed=True))

    # Test case 4: Isolated node
    n4 = 5
    edges4 = [(0,1), (1,2)]
    print("Test 4:", dfs(n4, edges4, 4, directed=False))

    # Test case 5: Invalid start node
    n5 = 3
    edges5 = [(0,1)]
    try:
        print("Test 5:", dfs(n5, edges5, 5, directed=False))
    except ValueError as e:
        print("Test 5: Error:", str(e))