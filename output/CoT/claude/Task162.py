
import heapq
from typing import Dict, List, Tuple

def dijkstra(graph: Dict[int, List[Tuple[int, int]]], start: int) -> Dict[int, int]:
    if graph is None or start not in graph:
        return {}
    
    distances = {vertex: float('inf') for vertex in graph}
    distances[start] = 0
    visited = set()
    pq = [(0, start)]
    
    while pq:
        current_distance, current_vertex = heapq.heappop(pq)
        
        if current_vertex in visited:
            continue
        visited.add(current_vertex)
        
        if current_vertex not in graph:
            continue
        
        for neighbor, weight in graph[current_vertex]:
            if weight < 0:
                continue  # Skip negative weights
            
            new_distance = distances[current_vertex] + weight
            
            if new_distance < distances[neighbor]:
                distances[neighbor] = new_distance
                heapq.heappush(pq, (new_distance, neighbor))
    
    # Convert infinity to None for unreachable nodes
    return {k: (v if v != float('inf') else None) for k, v in distances.items()}

if __name__ == "__main__":
    # Test Case 1: Simple graph
    graph1 = {
        0: [(1, 4), (2, 1)],
        1: [(3, 1)],
        2: [(1, 2), (3, 5)],
        3: []
    }
    print("Test Case 1:")
    print(dijkstra(graph1, 0))
    
    # Test Case 2: Disconnected graph
    graph2 = {
        0: [(1, 2)],
        1: [],
        2: [(3, 1)],
        3: []
    }
    print("\\nTest Case 2:")
    print(dijkstra(graph2, 0))
    
    # Test Case 3: Single node
    graph3 = {
        0: []
    }
    print("\\nTest Case 3:")
    print(dijkstra(graph3, 0))
    
    # Test Case 4: Multiple paths
    graph4 = {
        0: [(1, 10), (2, 5)],
        1: [(3, 1)],
        2: [(1, 3), (3, 9)],
        3: []
    }
    print("\\nTest Case 4:")
    print(dijkstra(graph4, 0))
    
    # Test Case 5: Larger graph
    graph5 = {
        0: [(1, 7), (2, 9), (5, 14)],
        1: [(0, 7), (2, 10), (3, 15)],
        2: [(0, 9), (1, 10), (3, 11), (5, 2)],
        3: [(1, 15), (2, 11), (4, 6)],
        4: [(3, 6), (5, 9)],
        5: [(0, 14), (2, 2), (4, 9)]
    }
    print("\\nTest Case 5:")
    print(dijkstra(graph5, 0))
