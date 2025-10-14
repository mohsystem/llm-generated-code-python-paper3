
import heapq
from typing import List, Tuple

def dijkstra(graph: List[List[Tuple[int, int]]], start: int, n: int) -> List[int]:
    distances = [float('inf')] * n
    distances[start] = 0
    
    pq = [(0, start)]
    visited = [False] * n
    
    while pq:
        current_dist, u = heapq.heappop(pq)
        
        if visited[u]:
            continue
        visited[u] = True
        
        for v, weight in graph[u]:
            if not visited[v] and distances[u] != float('inf') and distances[u] + weight < distances[v]:
                distances[v] = distances[u] + weight
                heapq.heappush(pq, (distances[v], v))
    
    return distances

if __name__ == "__main__":
    # Test Case 1: Simple graph
    print("Test Case 1:")
    n1 = 5
    graph1 = [[] for _ in range(n1)]
    graph1[0].append((1, 4))
    graph1[0].append((2, 1))
    graph1[1].append((3, 1))
    graph1[2].append((1, 2))
    graph1[2].append((3, 5))
    graph1[3].append((4, 3))
    result1 = dijkstra(graph1, 0, n1)
    print(result1)
    
    # Test Case 2: Single node
    print("\\nTest Case 2:")
    n2 = 1
    graph2 = [[]]
    result2 = dijkstra(graph2, 0, n2)
    print(result2)
    
    # Test Case 3: Disconnected graph
    print("\\nTest Case 3:")
    n3 = 4
    graph3 = [[] for _ in range(n3)]
    graph3[0].append((1, 1))
    graph3[1].append((0, 1))
    result3 = dijkstra(graph3, 0, n3)
    print(result3)
    
    # Test Case 4: Dense graph
    print("\\nTest Case 4:")
    n4 = 4
    graph4 = [[] for _ in range(n4)]
    graph4[0].append((1, 5))
    graph4[0].append((2, 10))
    graph4[1].append((2, 3))
    graph4[1].append((3, 8))
    graph4[2].append((3, 2))
    result4 = dijkstra(graph4, 0, n4)
    print(result4)
    
    # Test Case 5: Linear graph
    print("\\nTest Case 5:")
    n5 = 6
    graph5 = [[] for _ in range(n5)]
    graph5[0].append((1, 2))
    graph5[1].append((2, 3))
    graph5[2].append((3, 1))
    graph5[3].append((4, 4))
    graph5[4].append((5, 2))
    result5 = dijkstra(graph5, 0, n5)
    print(result5)
