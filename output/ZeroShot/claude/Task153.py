
from collections import deque
from typing import List, Dict

class Graph:
    def __init__(self, vertices):
        self.vertices = vertices
        self.adjacency_list = {i: [] for i in range(vertices)}
    
    def add_edge(self, source, destination):
        if 0 <= source < self.vertices and 0 <= destination < self.vertices:
            self.adjacency_list[source].append(destination)
    
    def breadth_first_search(self, start_node):
        result = []
        if start_node < 0 or start_node >= self.vertices:
            return result
        
        visited = [False] * self.vertices
        queue = deque()
        
        visited[start_node] = True
        queue.append(start_node)
        
        while queue:
            node = queue.popleft()
            result.append(node)
            
            for neighbor in self.adjacency_list[node]:
                if not visited[neighbor]:
                    visited[neighbor] = True
                    queue.append(neighbor)
        
        return result


def main():
    # Test Case 1: Simple linear graph
    print("Test Case 1: Linear Graph")
    graph1 = Graph(4)
    graph1.add_edge(0, 1)
    graph1.add_edge(1, 2)
    graph1.add_edge(2, 3)
    print(f"BFS from node 0: {graph1.breadth_first_search(0)}")
    
    # Test Case 2: Graph with multiple branches
    print("\\nTest Case 2: Branching Graph")
    graph2 = Graph(6)
    graph2.add_edge(0, 1)
    graph2.add_edge(0, 2)
    graph2.add_edge(1, 3)
    graph2.add_edge(1, 4)
    graph2.add_edge(2, 5)
    print(f"BFS from node 0: {graph2.breadth_first_search(0)}")
    
    # Test Case 3: Graph with cycle
    print("\\nTest Case 3: Graph with Cycle")
    graph3 = Graph(5)
    graph3.add_edge(0, 1)
    graph3.add_edge(1, 2)
    graph3.add_edge(2, 3)
    graph3.add_edge(3, 1)
    graph3.add_edge(0, 4)
    print(f"BFS from node 0: {graph3.breadth_first_search(0)}")
    
    # Test Case 4: Disconnected graph
    print("\\nTest Case 4: Disconnected Graph")
    graph4 = Graph(5)
    graph4.add_edge(0, 1)
    graph4.add_edge(2, 3)
    graph4.add_edge(3, 4)
    print(f"BFS from node 0: {graph4.breadth_first_search(0)}")
    
    # Test Case 5: Single node
    print("\\nTest Case 5: Single Node")
    graph5 = Graph(1)
    print(f"BFS from node 0: {graph5.breadth_first_search(0)}")


if __name__ == "__main__":
    main()
