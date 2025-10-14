
import heapq
from typing import Dict, List, Tuple, Optional

MAX_NODES: int = 10000
MAX_WEIGHT: int = 1000000

def dijkstra(graph: Dict[int, List[Tuple[int, int]]], start: int, node_count: int) -> Dict[int, int]:
    """\n    Find shortest paths from start node to all other nodes using Dijkstra's algorithm.\n    \n    Args:\n        graph: Adjacency list where graph[node] = [(neighbor, weight), ...]\n        start: Starting node index\n        node_count: Total number of nodes in the graph\n        \n    Returns:\n        Dictionary mapping node to shortest distance from start\n    """
    if graph is None or not isinstance(graph, dict):
        raise ValueError("Invalid graph")
    if not isinstance(node_count, int) or node_count <= 0 or node_count > MAX_NODES:
        raise ValueError("Invalid node count")
    if not isinstance(start, int) or start < 0 or start >= node_count:
        raise ValueError("Invalid start node")
    
    distances: Dict[int, int] = {i: float('inf') for i in range(node_count)}
    distances[start] = 0
    
    pq: List[Tuple[int, int]] = [(0, start)]
    visited: set = set()
    
    while pq:
        current_dist, current_node = heapq.heappop(pq)
        
        if current_node in visited:
            continue
        visited.add(current_node)
        
        if current_node not in graph:
            continue
            
        neighbors = graph[current_node]
        if not isinstance(neighbors, list):
            raise ValueError("Invalid neighbor list")
        if len(neighbors) > MAX_NODES:
            raise ValueError("Too many edges")
        
        for neighbor, weight in neighbors:
            if not isinstance(neighbor, int) or not isinstance(weight, int):
                raise ValueError("Invalid edge format")
            if neighbor < 0 or neighbor >= node_count:
                raise ValueError("Invalid neighbor node")
            if weight < 0 or weight > MAX_WEIGHT:
                raise ValueError("Invalid edge weight")
            
            if neighbor not in visited:
                new_dist = current_dist + weight
                
                if new_dist > 2**31 - 1:
                    new_dist = float('inf')
                
                if new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    heapq.heappush(pq, (new_dist, neighbor))
    
    return distances

def main() -> None:
    try:
        # Test case 1: Simple graph
        graph1: Dict[int, List[Tuple[int, int]]] = {
            0: [(1, 4), (2, 1)],
            1: [(3, 1)],
            2: [(1, 2), (3, 5)],
            3: []
        }
        result1 = dijkstra(graph1, 0, 4)
        print(f"Test 1 - Distances from node 0: {result1}")
        
        # Test case 2: Single node
        graph2: Dict[int, List[Tuple[int, int]]] = {
            0: []
        }
        result2 = dijkstra(graph2, 0, 1)
        print(f"Test 2 - Distances from node 0: {result2}")
        
        # Test case 3: Disconnected graph
        graph3: Dict[int, List[Tuple[int, int]]] = {
            0: [(1, 1)],
            1: [],
            2: []
        }
        result3 = dijkstra(graph3, 0, 3)
        print(f"Test 3 - Distances from node 0: {result3}")
        
        # Test case 4: Larger graph
        graph4: Dict[int, List[Tuple[int, int]]] = {
            0: [(1, 10), (2, 5)],
            1: [(3, 1), (2, 2)],
            2: [(1, 3), (3, 9), (4, 2)],
            3: [(4, 4)],
            4: []
        }
        result4 = dijkstra(graph4, 0, 5)
        print(f"Test 4 - Distances from node 0: {result4}")
        
        # Test case 5: Different starting node
        graph5: Dict[int, List[Tuple[int, int]]] = {
            0: [(1, 2)],
            1: [(2, 3)],
            2: [(0, 1)]
        }
        result5 = dijkstra(graph5, 1, 3)
        print(f"Test 5 - Distances from node 1: {result5}")
        
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
