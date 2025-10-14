from typing import List, Tuple

def dfs(n: int, edges: List[Tuple[int, int]], start: int, directed: bool = False) -> List[int]:
    adj: List[List[int]] = [[] for _ in range(n)]
    for u, v in edges:
        if 0 <= u < n and 0 <= v < n:
            adj[u].append(v)
            if not directed:
                adj[v].append(u)
    for nbrs in adj:
        nbrs.sort()
    order: List[int] = []
    if not (0 <= start < n):
        return order
    visited = [False] * n

    def rec(u: int):
        visited[u] = True
        order.append(u)
        for v in adj[u]:
            if not visited[v]:
                rec(v)

    rec(start)
    return order

if __name__ == "__main__":
    # Test 1: Line graph undirected
    n1 = 5
    e1 = [(0,1),(1,2),(2,3),(3,4)]
    print("Test1:", dfs(n1, e1, 0, directed=False))

    # Test 2: Branching undirected
    n2 = 6
    e2 = [(0,1),(0,2),(1,3),(1,4),(2,5)]
    print("Test2:", dfs(n2, e2, 0, directed=False))

    # Test 3: Cycle undirected
    n3 = 4
    e3 = [(0,1),(1,2),(2,0),(2,3)]
    print("Test3:", dfs(n3, e3, 0, directed=False))

    # Test 4: Disconnected, start isolated
    n4 = 5
    e4 = [(0,1),(1,2)]
    print("Test4:", dfs(n4, e4, 3, directed=False))

    # Test 5: Directed graph
    n5 = 5
    e5 = [(0,1),(0,2),(1,3),(3,4)]
    print("Test5:", dfs(n5, e5, 0, directed=True))