from collections import deque
from typing import List, Tuple

def bfs(n: int, edges: List[Tuple[int, int]], start: int, undirected: bool = False) -> List[int]:
    result: List[int] = []
    if n <= 0 or start < 0 or start >= n:
        return result

    # Build adjacency with dedup using sets
    adj = [set() for _ in range(n)]
    if edges:
        for e in edges:
            if e is None or len(e) < 2:
                continue
            u, v = e
            if not isinstance(u, int) or not isinstance(v, int):
                continue
            if u < 0 or u >= n or v < 0 or v >= n:
                continue
            adj[u].add(v)
            if undirected and u != v:
                adj[v].add(u)

    # Convert to sorted lists for deterministic traversal
    adj_lists = [sorted(list(neigh)) for neigh in adj]

    visited = [False] * n
    q: deque[int] = deque()
    visited[start] = True
    q.append(start)

    while q:
        u = q.popleft()
        result.append(u)
        for v in adj_lists[u]:
            if not visited[v]:
                visited[v] = True
                q.append(v)
    return result

if __name__ == "__main__":
    # Test 1: Simple undirected chain
    print("Test 1:", bfs(4, [(0,1),(1,2),(2,3)], 0, True))
    # Test 2: Undirected graph with cycles
    print("Test 2:", bfs(4, [(0,1),(0,2),(1,2),(2,3)], 1, True))
    # Test 3: Disconnected graph
    print("Test 3:", bfs(5, [(3,4)], 3, True))
    # Test 4: Directed cycle
    print("Test 4:", bfs(3, [(0,1),(1,2),(2,0)], 1, False))
    # Test 5: Invalid edges and self-loop
    print("Test 5:", bfs(4, [(-1,2),(1,4),(0,0)], 0, True))