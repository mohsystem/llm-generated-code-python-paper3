
from typing import List, Dict, Set
from collections import deque

MAX_NODES = 10000
MAX_EDGES = 100000

class Graph:
    def __init__(self, max_nodes: int):
        if max_nodes <= 0 or max_nodes > MAX_NODES:
            raise ValueError("Invalid max_nodes")
        self.max_nodes = max_nodes
        self.adjacency_list: Dict[int, List[int]] = {}
    
    def add_edge(self, from_node: int, to_node: int) -> None:
        if from_node < 0 or from_node >= self.max_nodes or to_node < 0 or to_node >= self.max_nodes:
            raise ValueError("Invalid node")
        if from_node not in self.adjacency_list:
            self.adjacency_list[from_node] = []
        self.adjacency_list[from_node].append(to_node)
    
    def get_neighbors(self, node: int) -> List[int]:
        if node < 0 or node >= self.max_nodes:
            raise ValueError("Invalid node")
        return self.adjacency_list.get(node, [])

def breadth_first_search(graph: Graph, start_node: int) -> List[int]:
    if graph is None:
        raise ValueError("Graph cannot be None")
    if start_node < 0 or start_node >= graph.max_nodes:
        raise ValueError("Invalid start node")
    
    result: List[int] = []
    visited: Set[int] = set()
    queue: deque = deque()
    
    queue.append(start_node)
    visited.add(start_node)
    
    while queue:
        current = queue.popleft()
        result.append(current)
        
        for neighbor in graph.get_neighbors(current):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    
    return result

def main():
    # Test case 1: Simple linear graph
    graph1 = Graph(5)
    graph1.add_edge(0, 1)
    graph1.add_edge(1, 2)
    graph1.add_edge(2, 3)
    graph1.add_edge(3, 4)
    result1 = breadth_first_search(graph1, 0)
    print(f"Test 1: {result1}")
    
    # Test case 2: Tree structure
    graph2 = Graph(7)
    graph2.add_edge(0, 1)
    graph2.add_edge(0, 2)
    graph2.add_edge(1, 3)
    graph2.add_edge(1, 4)
    graph2.add_edge(2, 5)
    graph2.add_edge(2, 6)
    result2 = breadth_first_search(graph2, 0)
    print(f"Test 2: {result2}")
    
    # Test case 3: Graph with cycle
    graph3 = Graph(4)
    graph3.add_edge(0, 1)
    graph3.add_edge(1, 2)
    graph3.add_edge(2, 3)
    graph3.add_edge(3, 1)
    result3 = breadth_first_search(graph3, 0)
    print(f"Test 3: {result3}")
    
    # Test case 4: Disconnected graph
    graph4 = Graph(6)
    graph4.add_edge(0, 1)
    graph4.add_edge(1, 2)
    graph4.add_edge(3, 4)
    graph4.add_edge(4, 5)
    result4 = breadth_first_search(graph4, 0)
    print(f"Test 4: {result4}")
    
    # Test case 5: Single node
    graph5 = Graph(1)
    result5 = breadth_first_search(graph5, 0)
    print(f"Test 5: {result5}")

if __name__ == "__main__":
    main()
