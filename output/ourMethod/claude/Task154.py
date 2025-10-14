
from typing import Dict, List, Set

MAX_NODES = 10000
MAX_EDGES = 100000

def depth_first_search(graph: Dict[int, List[int]], start_node: int) -> List[int]:
    if graph is None:
        raise ValueError("Graph cannot be None")
    
    if not isinstance(graph, dict):
        raise TypeError("Graph must be a dictionary")
    
    if not isinstance(start_node, int):
        raise TypeError("Start node must be an integer")
    
    if start_node not in graph:
        raise ValueError("Start node not found in graph")
    
    if len(graph) > MAX_NODES:
        raise ValueError("Graph exceeds maximum node limit")
    
    edge_count = 0
    for neighbors in graph.values():
        if neighbors is not None:
            if not isinstance(neighbors, list):
                raise TypeError("Neighbors must be a list")
            edge_count += len(neighbors)
    
    if edge_count > MAX_EDGES:
        raise ValueError("Graph exceeds maximum edge limit")
    
    result: List[int] = []
    visited: Set[int] = set()
    _dfs_helper(graph, start_node, visited, result)
    return result

def _dfs_helper(graph: Dict[int, List[int]], node: int, 
                visited: Set[int], result: List[int]) -> None:
    if node in visited:
        return
    
    visited.add(node)
    result.append(node)
    
    neighbors = graph.get(node)
    if neighbors is not None:
        for neighbor in neighbors:
            if neighbor is None:
                continue
            if not isinstance(neighbor, int):
                continue
            if neighbor not in graph:
                continue
            _dfs_helper(graph, neighbor, visited, result)

if __name__ == "__main__":
    # Test case 1: Simple linear graph
    graph1 = {
        1: [2],
        2: [3],
        3: []
    }
    print(f"Test 1: {depth_first_search(graph1, 1)}")
    
    # Test case 2: Graph with branches
    graph2 = {
        1: [2, 3],
        2: [4],
        3: [5],
        4: [],
        5: []
    }
    print(f"Test 2: {depth_first_search(graph2, 1)}")
    
    # Test case 3: Graph with cycle
    graph3 = {
        1: [2],
        2: [3],
        3: [1, 4],
        4: []
    }
    print(f"Test 3: {depth_first_search(graph3, 1)}")
    
    # Test case 4: Single node
    graph4 = {
        1: []
    }
    print(f"Test 4: {depth_first_search(graph4, 1)}")
    
    # Test case 5: Disconnected components
    graph5 = {
        1: [2],
        2: [],
        3: [4],
        4: []
    }
    print(f"Test 5: {depth_first_search(graph5, 1)}")
