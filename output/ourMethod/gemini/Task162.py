import heapq
from typing import List, Tuple

def dijkstra(V: int, adj: List[List[Tuple[int, int]]], start_node: int) -> List[int]:
    """
    Implements Dijkstra's algorithm to find the shortest path from a starting node.

    :param V: The number of vertices in the graph.
    :param adj: The adjacency list representation of the graph, where adj[i] contains
                a list of tuples (neighbor, weight).
    :param start_node: The starting node.
    :return: A list containing the shortest distances from the start node to all other nodes.
    """
    if V <= 0 or not (0 <= start_node < V):
        raise ValueError("Invalid input: V must be positive and start_node must be a valid index.")
    
    distances = [float('inf')] * V
    distances[start_node] = 0
    
    # Priority queue stores (distance, vertex)
    pq = [(0, start_node)]
    
    while pq:
        dist, u = heapq.heappop(pq)
        
        # If we've found a shorter path already, skip
        if dist > distances[u]:
            continue
        
        for v, weight in adj[u]:
            # Relaxation step
            if distances[u] != float('inf') and distances[u] + weight < distances[v]:
                distances[v] = distances[u] + weight
                heapq.heappush(pq, (distances[v], v))
                
    return distances

def print_distances(distances: List[int], start_node: int):
    """Helper function to print distances."""
    print(f"Shortest distances from source node {start_node}:")
    for i, d in enumerate(distances):
        print(f"Node {i}: {d}")

def main():
    """Main function with test cases."""
    # Test Case 1: Standard case
    V1 = 5
    adj1 = [[] for _ in range(V1)]
    adj1[0].extend([(1, 9), (2, 6), (3, 5), (4, 3)])
    adj1[2].extend([(1, 2), (3, 4)])
    start_node1 = 0
    print("Test Case 1: Standard graph from source 0")
    distances1 = dijkstra(V1, adj1, start_node1)
    print_distances(distances1, start_node1)
    print()

    # Test Case 2: Graph with unreachable nodes
    V2 = 6
    adj2 = [[] for _ in range(V2)]
    adj2[0].extend([(1, 7), (2, 9)])
    adj2[1].extend([(2, 10), (3, 15)])
    adj2[2].append((3, 11))
    # Node 4 and 5 are unreachable from 0
    adj2[4].append((5, 6))
    start_node2 = 0
    print("Test Case 2: Graph with unreachable nodes from source 0")
    distances2 = dijkstra(V2, adj2, start_node2)
    print_distances(distances2, start_node2)
    print()

    # Test Case 3: Different starting node
    start_node3 = 3
    print("Test Case 3: Same as graph 1, but from source 3")
    # Re-using graph from test case 1, start node 3
    distances3 = dijkstra(V1, adj1, start_node3)
    print_distances(distances3, start_node3)
    print()

    # Test Case 4: Linear graph
    V4 = 4
    adj4 = [[] for _ in range(V4)]
    adj4[0].append((1, 10))
    adj4[1].append((2, 20))
    adj4[2].append((3, 30))
    start_node4 = 0
    print("Test Case 4: Linear graph from source 0")
    distances4 = dijkstra(V4, adj4, start_node4)
    print_distances(distances4, start_node4)
    print()
    
    # Test Case 5: Invalid input
    print("Test Case 5: Invalid start node")
    try:
        dijkstra(V1, adj1, -1)
    except ValueError as e:
        print(f"Caught expected exception: {e}")

if __name__ == "__main__":
    main()