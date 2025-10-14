import heapq

INF = (1 << 62)

def dijkstra(n, adj, start):
    if not isinstance(n, int) or n <= 0:
        raise ValueError("Number of nodes must be positive.")
    if not isinstance(adj, list) or len(adj) != n:
        raise ValueError("Adjacency list must be a list of length n.")
    if not isinstance(start, int) or not (0 <= start < n):
        raise ValueError("Start node out of range.")
    for u, edges in enumerate(adj):
        if edges is None:
            raise ValueError(f"Adjacency for node {u} is None.")
        for e in edges:
            if not (isinstance(e, tuple) or isinstance(e, list)) or len(e) != 2:
                raise ValueError("Edges must be (to, weight).")
            v, w = e
            if not (isinstance(v, int) and 0 <= v < n):
                raise ValueError("Edge endpoint out of range.")
            if not (isinstance(w, int) or isinstance(w, float)) or w < 0:
                raise ValueError("Negative weights not allowed for Dijkstra.")

    dist = [INF] * n
    visited = [False] * n
    dist[start] = 0
    pq = [(0, start)]

    while pq:
        d, u = heapq.heappop(pq)
        if visited[u]:
            continue
        visited[u] = True
        for v, w in adj[u]:
            if visited[v]:
                continue
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    return dist

def _print_result(dist):
    out = []
    for d in dist:
        out.append("INF" if d >= INF else str(d))
    print(" ".join(out))

def main():
    # Test case 1
    n = 5; s = 0
    adj = [[] for _ in range(n)]
    adj[0].append((1, 2))
    adj[0].append((2, 5))
    adj[1].append((2, 1))
    adj[1].append((3, 2))
    adj[2].append((3, 1))
    adj[3].append((4, 3))
    _print_result(dijkstra(n, adj, s))  # 0 2 3 4 7

    # Test case 2
    n = 5; s = 0
    adj = [[] for _ in range(n)]
    adj[0].append((1, 1))
    adj[1].append((2, 1))
    adj[2].append((3, 1))
    adj[3].append((4, 1))
    _print_result(dijkstra(n, adj, s))  # 0 1 2 3 4

    # Test case 3
    n = 5; s = 0
    adj = [[] for _ in range(n)]
    adj[0].append((1, 10))
    adj[0].append((2, 3))
    adj[2].append((1, 1))
    adj[2].append((3, 2))
    adj[1].append((3, 4))
    adj[3].append((4, 2))
    adj[4].append((1, 1))
    _print_result(dijkstra(n, adj, s))  # 0 4 3 5 7

    # Test case 4 (disconnected)
    n = 5; s = 0
    adj = [[] for _ in range(n)]
    adj[1].append((2, 2))
    adj[2].append((3, 2))
    _print_result(dijkstra(n, adj, s))  # 0 INF INF INF INF

    # Test case 5 (classic)
    n = 6; s = 0
    adj = [[] for _ in range(n)]
    adj[0].append((1, 7))
    adj[0].append((2, 9))
    adj[0].append((5, 14))
    adj[1].append((2, 10))
    adj[1].append((3, 15))
    adj[2].append((3, 11))
    adj[2].append((5, 2))
    adj[3].append((4, 6))
    adj[4].append((5, 9))
    _print_result(dijkstra(n, adj, s))  # 0 7 9 20 26 11

if __name__ == "__main__":
    main()