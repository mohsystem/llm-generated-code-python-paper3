
class Task154:
    def __init__(self):
        self.adjacency_list = {}
    
    def add_edge(self, source, destination):
        if source < 0 or destination < 0:
            raise ValueError("Node values must be non-negative")
        
        if source not in self.adjacency_list:
            self.adjacency_list[source] = []
        if destination not in self.adjacency_list:
            self.adjacency_list[destination] = []
        
        self.adjacency_list[source].append(destination)
    
    def depth_first_search(self, start_node):
        if start_node < 0:
            raise ValueError("Start node must be non-negative")
        
        result = []
        visited = set()
        
        if start_node not in self.adjacency_list:
            return result
        
        self._dfs_helper(start_node, visited, result)
        return result
    
    def _dfs_helper(self, node, visited, result):
        if node in visited:
            return
        
        visited.add(node)
        result.append(node)
        
        neighbors = self.adjacency_list.get(node, [])
        for neighbor in neighbors:
            if neighbor not in visited:
                self._dfs_helper(neighbor, visited, result)


def main():
    # Test Case 1: Simple linear graph
    print("Test Case 1: Linear Graph")
    graph1 = Task154()
    graph1.add_edge(1, 2)
    graph1.add_edge(2, 3)
    graph1.add_edge(3, 4)
    print(f"DFS from node 1: {graph1.depth_first_search(1)}")
    
    # Test Case 2: Graph with branches
    print("\\nTest Case 2: Branched Graph")
    graph2 = Task154()
    graph2.add_edge(1, 2)
    graph2.add_edge(1, 3)
    graph2.add_edge(2, 4)
    graph2.add_edge(2, 5)
    graph2.add_edge(3, 6)
    print(f"DFS from node 1: {graph2.depth_first_search(1)}")
    
    # Test Case 3: Graph with cycle
    print("\\nTest Case 3: Graph with Cycle")
    graph3 = Task154()
    graph3.add_edge(1, 2)
    graph3.add_edge(2, 3)
    graph3.add_edge(3, 1)
    graph3.add_edge(3, 4)
    print(f"DFS from node 1: {graph3.depth_first_search(1)}")
    
    # Test Case 4: Disconnected graph
    print("\\nTest Case 4: Disconnected Graph")
    graph4 = Task154()
    graph4.add_edge(1, 2)
    graph4.add_edge(3, 4)
    graph4.add_edge(5, 6)
    print(f"DFS from node 1: {graph4.depth_first_search(1)}")
    print(f"DFS from node 3: {graph4.depth_first_search(3)}")
    
    # Test Case 5: Single node
    print("\\nTest Case 5: Single Node")
    graph5 = Task154()
    graph5.add_edge(1, 1)
    print(f"DFS from node 1: {graph5.depth_first_search(1)}")


if __name__ == "__main__":
    main()
