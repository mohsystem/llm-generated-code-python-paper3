
from collections import deque, defaultdict
from typing import List, Dict, Set

class Task153:
    def __init__(self):
        self.adjacency_list: Dict[int, List[int]] = defaultdict(list)
    
    def add_edge(self, source: int, destination: int) -> None:
        if source < 0 or destination < 0:
            raise ValueError("Node values must be non-negative")
        self.adjacency_list[source].append(destination)
        if destination not in self.adjacency_list:
            self.adjacency_list[destination] = []
    
    def breadth_first_search(self, start_node: int) -> List[int]:
        if start_node < 0:
            raise ValueError("Start node must be non-negative")
        
        result: List[int] = []
        if start_node not in self.adjacency_list:
            return result
        
        visited: Set[int] = set()
        queue: deque = deque()
        
        queue.append(start_node)
        visited.add(start_node)
        
        while queue:
            current_node = queue.popleft()
            result.append(current_node)
            
            neighbors = self.adjacency_list.get(current_node, [])
            for neighbor in neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        
        return result

def main():
    # Test case 1: Simple linear graph
    print("Test Case 1: Linear Graph")
    graph1 = Task153()
    graph1.add_edge(1, 2)
    graph1.add_edge(2, 3)
    graph1.add_edge(3, 4)
    print(f"BFS from node 1: {graph1.breadth_first_search(1)}")
    
    # Test case 2: Graph with multiple branches
    print("\\nTest Case 2: Graph with Multiple Branches")
    graph2 = Task153()
    graph2.add_edge(0, 1)
    graph2.add_edge(0, 2)
    graph2.add_edge(1, 3)
    graph2.add_edge(1, 4)
    graph2.add_edge(2, 5)
    print(f"BFS from node 0: {graph2.breadth_first_search(0)}")
    
    # Test case 3: Disconnected graph
    print("\\nTest Case 3: Disconnected Graph")
    graph3 = Task153()
    graph3.add_edge(0, 1)
    graph3.add_edge(2, 3)
    print(f"BFS from node 0: {graph3.breadth_first_search(0)}")
    
    # Test case 4: Graph with cycle
    print("\\nTest Case 4: Graph with Cycle")
    graph4 = Task153()
    graph4.add_edge(0, 1)
    graph4.add_edge(1, 2)
    graph4.add_edge(2, 0)
    graph4.add_edge(2, 3)
    print(f"BFS from node 0: {graph4.breadth_first_search(0)}")
    
    # Test case 5: Single node
    print("\\nTest Case 5: Single Node")
    graph5 = Task153()
    graph5.add_edge(5, 5)
    print(f"BFS from node 5: {graph5.breadth_first_search(5)}")

if __name__ == "__main__":
    main()
