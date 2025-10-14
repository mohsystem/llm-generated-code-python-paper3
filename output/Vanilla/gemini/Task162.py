import heapq
import sys

def dijkstra(V, adj, start_node):
    """
    Finds the shortest paths from a starting node to all other nodes in a weighted graph.

    :param V: The number of vertices in the graph.
    :param adj: The adjacency list as a dictionary {u: [(v, w), ...]}.
    :param start_node: The starting node.
    :return: A list containing the shortest distances from the start node.
    """
    dist = [sys.maxsize] * V
    dist[start_node] = 0
    pq = [(0, start_node)]  # (distance, vertex)

    while pq:
        d, u = heapq.heappop(pq)

        if d > dist[u]:
            continue

        for v, weight in adj.get(u, []):
            if dist[u] + weight < dist[v]:
                dist[v] = dist[u] + weight
                heapq.heappush(pq, (dist[v], v))
    
    return dist

def main():
    # Test Case 1: Simple connected graph
    print("--- Test Case 1 ---")
    V1 = 5
    adj1 = {
        0: [(1, 9), (2, 6), (3, 5), (4, 3)],
        2: [(1, 2), (3, 4)]
    }
    start_node1 = 0
    dist1 = dijkstra(V1, adj1, start_node1)
    print(f"Shortest distances from node {start_node1}: {dist1}")

    # Test Case 2: Graph with unreachable node
    print("\n--- Test Case 2 ---")
    V2 = 4
    adj2 = {
        0: [(1, 10)],
        1: [(2, 20)]
    }
    start_node2 = 0
    dist2 = dijkstra(V2, adj2, start_node2)
    dist2_str = ["INF" if d == sys.maxsize else d for d in dist2]
    print(f"Shortest distances from node {start_node2}: {dist2_str}")

    # Test Case 3: Linear graph
    print("\n--- Test Case 3 ---")
    V3 = 4
    adj3 = {
        0: [(1, 5)],
        1: [(2, 5)],
        2: [(3, 5)]
    }
    start_node3 = 0
    dist3 = dijkstra(V3, adj3, start_node3)
    print(f"Shortest distances from node {start_node3}: {dist3}")

    # Test Case 4: Graph with a cycle
    print("\n--- Test Case 4 ---")
    V4 = 4
    adj4 = {
        0: [(1, 1), (3, 10)],
        1: [(2, 2)],
        2: [(0, 3)]
    }
    start_node4 = 0
    dist4 = dijkstra(V4, adj4, start_node4)
    print(f"Shortest distances from node {start_node4}: {dist4}")

    # Test Case 5: More complex graph with multiple paths
    print("\n--- Test Case 5 ---")
    V5 = 6
    adj5 = {
        0: [(1, 7), (2, 9), (5, 14)],
        1: [(2, 10), (3, 15)],
        2: [(3, 11), (5, 2)],
        3: [(4, 6)],
        4: [(5, 9)]
    }
    start_node5 = 0
    dist5 = dijkstra(V5, adj5, start_node5)
    print(f"Shortest distances from node {start_node5}: {dist5}")

if __name__ == "__main__":
    main()