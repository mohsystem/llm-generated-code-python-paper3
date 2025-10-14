import heapq

def dijkstra(n, edges, start):
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        adj[u].append((v, w))
    INF = 10**18
    dist = [INF] * n
    dist[start] = 0
    pq = [(0, start)]
    visited = [False]*n
    while pq:
        d, u = heapq.heappop(pq)
        if visited[u]:
            continue
        visited[u] = True
        for v, w in adj[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    return dist

def _print(dist):
    print(" ".join("INF" if x >= 10**17 else str(x) for x in dist))

if __name__ == "__main__":
    # Test 1
    n1 = 5
    edges1 = [
        (0,1,10),(0,2,3),(1,2,1),(2,1,4),(1,3,2),(2,3,2),(3,4,7),(2,4,8),(4,3,9)
    ]
    _print(dijkstra(n1, edges1, 0))  # Expected: 0 7 3 5 11

    # Test 2 (undirected)
    n2 = 4
    edges2 = [
        (0,1,5),(1,0,5),(1,2,6),(2,1,6),(0,3,10),(3,0,10),(2,3,2),(3,2,2)
    ]
    _print(dijkstra(n2, edges2, 0))  # Expected: 0 5 11 10

    # Test 3 (unreachable)
    n3 = 4
    edges3 = [
        (0,1,2)
    ]
    _print(dijkstra(n3, edges3, 0))  # Expected: 0 2 INF INF

    # Test 4 (zero-weight chain)
    n4 = 5
    edges4 = [
        (0,1,0),(1,2,0),(2,3,0),(3,4,0)
    ]
    _print(dijkstra(n4, edges4, 0))  # Expected: 0 0 0 0 0

    # Test 5 (undirected classic)
    n5 = 6
    edges5 = [
        (0,1,7),(1,0,7),(0,2,9),(2,0,9),(0,5,14),(5,0,14),
        (1,2,10),(2,1,10),(1,3,15),(3,1,15),(2,3,11),(3,2,11),
        (2,5,2),(5,2,2),(3,4,6),(4,3,6),(4,5,9),(5,4,9)
    ]
    _print(dijkstra(n5, edges5, 0))  # Expected: 0 7 9 20 20 11