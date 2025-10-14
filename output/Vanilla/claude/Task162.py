
import heapq

def dijkstra(graph, start, n):
    distances = [float('inf')] * n
    distances[start] = 0
    
    pq = [(0, start)]
    visited = set()
    
    while pq:
        current_dist, u = heapq.heappop(pq)
        
        if u in visited:
            continue
        visited.add(u)
        
        if u in graph:
            for v, weight in graph[u]:
                if v not in visited and distances[u] + weight < distances[v]:
                    distances[v] = distances[u] + weight
                    heapq.heappush(pq, (distances[v], v))
    
    return distances


if __name__ == "__main__":
    # Test Case 1: Simple graph
    graph1 = {
        0: [(1, 4), (2, 1)],
        1: [(3, 1)],
        2: [(1, 2), (3, 5)],
        3: [(4, 3)],
        4: []
    }
    print("Test Case 1:")
    print("Start node: 0")
    print("Shortest distances:", dijkstra(graph1, 0, 5))
    
    # Test Case 2: Disconnected node
    graph2 = {
        0: [(1, 5)],
        1: [(2, 3)],
        2: [],
        3: []
    }
    print("\\nTest Case 2:")
    print("Start node: 0")
    print("Shortest distances:", dijkstra(graph2, 0, 4))
    
    # Test Case 3: Complete graph
    graph3 = {
        0: [(1, 2), (2, 5)],
        1: [(2, 1)],
        2: []
    }
    print("\\nTest Case 3:")
    print("Start node: 0")
    print("Shortest distances:", dijkstra(graph3, 0, 3))
    
    # Test Case 4: Single node
    graph4 = {0: []}
    print("\\nTest Case 4:")
    print("Start node: 0")
    print("Shortest distances:", dijkstra(graph4, 0, 1))
    
    # Test Case 5: Multiple paths
    graph5 = {
        0: [(1, 7), (2, 9), (5, 14)],
        1: [(2, 10), (3, 15)],
        2: [(3, 11), (5, 2)],
        3: [(4, 6)],
        4: [(5, 9)],
        5: []
    }
    print("\\nTest Case 5:")
    print("Start node: 0")
    print("Shortest distances:", dijkstra(graph5, 0, 6))
