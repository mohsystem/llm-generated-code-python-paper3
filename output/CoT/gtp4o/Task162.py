# Chain-of-Through process:
# 1) Problem understanding: Implement Dijkstra for non-negative weighted graph.
# 2) Security: Validate indices and weights; handle unreachable nodes; avoid unsafe operations.
# 3) Secure coding: Use heapq, adjacency with validation, safe arithmetic (Python ints are unbounded).
# 4) Review: Defensive checks, skip invalid edges, no external input.
# 5) Output: Clean, safe implementation with tests.

import heapq
from typing import List, Tuple, Dict

def dijkstra(n: int, edges: List[Tuple[int, int, int]], start: int) -> Tuple[List[int], List[int]]:
    if n <= 0:
        raise ValueError("Number of nodes must be positive")
    if start < 0 or start >= n:
        raise ValueError("Start node out of range")

    g: List[List[Tuple[int, int]]] = [[] for _ in range(n)]
    for e in edges:
        if e is None or len(e) < 3:
            continue
        u, v, w = e
        if not isinstance(u, int) or not isinstance(v, int) or not isinstance(w, int):
            continue
        if u < 0 or u >= n or v < 0 or v >= n:
            continue
        if w < 0:
            continue
        g[u].append((v, w))

    INF = 10**18
    dist = [INF] * n
    parent = [-1] * n
    dist[start] = 0

    pq: List[Tuple[int, int]] = [(0, start)]
    while pq:
        d, u = heapq.heappop(pq)
        if d != dist[u]:
            continue
        for v, w in g[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                parent[v] = u
                heapq.heappush(pq, (nd, v))
    return dist, parent

def _print_list(lst):
    print("[" + ", ".join(("INF" if isinstance(x, int) and x >= 10**18//2 else str(x)) for x in lst) + "]")

def main():
    # Test 1
    n1 = 5
    edges1 = [
        (0,1,10),(0,2,3),(1,2,1),(1,3,2),(2,1,4),(2,3,8),(2,4,2),(3,4,7),(4,3,9)
    ]
    d1, p1 = dijkstra(n1, edges1, 0)
    print("Test 1 distances:"); _print_list(d1)
    print("Test 1 parents:"); _print_list(p1)

    # Test 2 (zero-weight)
    n2 = 4
    edges2 = [
        (0,1,0),(0,2,5),(1,2,1),(1,3,4),(2,3,0)
    ]
    d2, p2 = dijkstra(n2, edges2, 0)
    print("Test 2 distances:"); _print_list(d2)
    print("Test 2 parents:"); _print_list(p2)

    # Test 3 (disconnected)
    n3 = 5
    edges3 = [
        (0,1,2),(1,2,2)
    ]
    d3, p3 = dijkstra(n3, edges3, 0)
    print("Test 3 distances:"); _print_list(d3)
    print("Test 3 parents:"); _print_list(p3)

    # Test 4 (undirected classic: both directions)
    n4 = 6
    edges4 = [
        (0,1,7),(1,0,7),(0,2,9),(2,0,9),(0,5,14),(5,0,14),
        (1,2,10),(2,1,10),(1,3,15),(3,1,15),(2,3,11),(3,2,11),
        (2,5,2),(5,2,2),(3,4,6),(4,3,6),(4,5,9),(5,4,9)
    ]
    d4, p4 = dijkstra(n4, edges4, 0)
    print("Test 4 distances:"); _print_list(d4)
    print("Test 4 parents:"); _print_list(p4)

    # Test 5 (directed asymmetric)
    n5 = 5
    edges5 = [
        (0,1,2),(1,2,3),(0,2,10),(2,3,1),(3,4,1),(1,4,100)
    ]
    d5, p5 = dijkstra(n5, edges5, 0)
    print("Test 5 distances:"); _print_list(d5)
    print("Test 5 parents:"); _print_list(p5)

if __name__ == "__main__":
    main()