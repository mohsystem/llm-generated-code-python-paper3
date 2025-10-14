from typing import List, Optional, Tuple
import heapq

INF = 10**18

def dijkstra(n: int, edges: List[Tuple[int, int, int]], start: int) -> Optional[List[int]]:
    if not isinstance(n, int) or n <= 0:
        return None
    if not isinstance(start, int) or start < 0 or start >= n:
        return None
    if edges is None:
        edges = []

    graph: List[List[Tuple[int, int]]] = [[] for _ in range(n)]
    for e in edges:
        if not isinstance(e, (list, tuple)) or len(e) != 3:
            return None
        u, v, w = e
        if not (isinstance(u, int) and isinstance(v, int) and isinstance(w, int)):
            return None
        if u < 0 or u >= n or v < 0 or v >= n or w < 0:
            return None
        if w > INF // 2:
            return None
        graph[u].append((v, w))

    dist = [INF] * n
    dist[start] = 0
    visited = [False] * n
    pq: List[Tuple[int, int]] = [(0, start)]

    while pq:
        d, u = heapq.heappop(pq)
        if visited[u]:
            continue
        visited[u] = True
        for v, w in graph[u]:
            alt = d + w
            if alt < dist[v]:
                dist[v] = alt
                heapq.heappush(pq, (alt, v))
    return dist

def _print_result(title: str, dist: Optional[List[int]]) -> None:
    print(title)
    if dist is None:
        print("Invalid input")
        return
    out = []
    for x in dist:
        out.append("INF" if x >= INF else str(x))
    print(" ".join(out))

def main() -> None:
    # Test 1: Simple directed graph
    n1 = 3
    edges1 = [(0, 1, 4), (0, 2, 1), (2, 1, 2)]
    _print_result("Test 1", dijkstra(n1, edges1, 0))

    # Test 2: Disconnected nodes
    n2 = 4
    edges2 = [(0, 1, 5)]
    _print_result("Test 2", dijkstra(n2, edges2, 0))

    # Test 3: Zero-weight edges
    n3 = 4
    edges3 = [(0, 1, 0), (1, 2, 0), (2, 3, 1)]
    _print_result("Test 3", dijkstra(n3, edges3, 0))

    # Test 4: Larger weights with alternative shorter path
    n4 = 5
    edges4 = [(0, 1, 1_000_000_000), (1, 2, 1_000_000_000), (0, 3, 1), (3, 4, 1), (4, 2, 1)]
    _print_result("Test 4", dijkstra(n4, edges4, 0))

    # Test 5: Invalid input (negative weight)
    n5 = 2
    edges5 = [(0, 1, -1)]
    _print_result("Test 5", dijkstra(n5, edges5, 0))

if __name__ == "__main__":
    main()