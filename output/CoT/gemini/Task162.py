import heapq
import sys

def dijkstra(V, adj, src):
    """
    Implements Dijkstra's algorithm to find the shortest path from a source
    node to all other nodes in a weighted graph.

    :param V: The number of vertices in the graph.
    :param adj: The adjacency list representation of the graph.
    :param src: The source vertex.
    :return: A list containing the shortest distances from the source vertex.
    """
    dist = [float('inf')] * V
    dist[src] = 0
    
    pq = [(0, src)]  # (distance, vertex)

    while pq:
        d, u = heapq.heappop(pq)

        # If we've found a shorter path already, skip
        if d > dist[u]:
            continue

        for v, weight in adj[u]:
            # Relaxation step
            if dist[u] + weight < dist[v]:
                dist[v] = dist[u] + weight
                heapq.heappush(pq, (dist[v], v))
    
    return dist

def main():
    # --- Test Case 1: Simple Graph ---
    print("--- Test Case 1 ---")
    V1, src1 = 5, 0
    adj1 = [[] for _ in range(V1)]
    edges1 = [(0, 1, 10), (0, 3, 5), (1, 2, 1), (1, 3, 2), (2, 4, 4), 
              (3, 1, 3), (3, 2, 9), (3, 4, 2), (4, 0, 7), (4, 2, 6)]
    for u, v, w in edges1:
        adj1[u].append((v, w))
    dist1 = dijkstra(V1, adj1, src1)
    print(f"Distances from source {src1}: {dist1}")

    # --- Test Case 2: Disconnected Graph ---
    print("\n--- Test Case 2 ---")
    V2, src2 = 6, 0
    adj2 = [[] for _ in range(V2)]
    edges2 = [(0, 1, 2), (1, 2, 3), (3, 4, 5), (4, 5, 6)]
    for u, v, w in edges2:
        adj2[u].append((v, w))
    dist2 = dijkstra(V2, adj2, src2)
    print(f"Distances from source {src2}: {dist2}")

    # --- Test Case 3: Line Graph ---
    print("\n--- Test Case 3 ---")
    V3, src3 = 4, 0
    adj3 = [[] for _ in range(V3)]
    edges3 = [(0, 1, 1), (1, 2, 2), (2, 3, 3)]
    for u, v, w in edges3:
        adj3[u].append((v, w))
    dist3 = dijkstra(V3, adj3, src3)
    print(f"Distances from source {src3}: {dist3}")

    # --- Test Case 4: Graph with alternative paths ---
    print("\n--- Test Case 4 ---")
    V4, src4 = 6, 0
    adj4 = [[] for _ in range(V4)]
    edges4 = [(0, 1, 4), (0, 2, 1), (1, 3, 1), (2, 1, 2), 
              (2, 3, 5), (3, 4, 3), (4, 5, 2), (2, 5, 10)]
    for u, v, w in edges4:
        adj4[u].append((v, w))
    dist4 = dijkstra(V4, adj4, src4)
    print(f"Distances from source {src4}: {dist4}")

    # --- Test Case 5: Single Node Graph ---
    print("\n--- Test Case 5 ---")
    V5, src5 = 1, 0
    adj5 = [[] for _ in range(V5)]
    dist5 = dijkstra(V5, adj5, src5)
    print(f"Distances from source {src5}: {dist5}")

if __name__ == "__main__":
    main()