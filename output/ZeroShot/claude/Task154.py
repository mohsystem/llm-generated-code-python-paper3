
class Graph:
    def __init__(self, vertices):
        self.vertices = vertices
        self.adjacency_list = [[] for _ in range(vertices)]
    
    def add_edge(self, source, destination):
        if 0 <= source < self.vertices and 0 <= destination < self.vertices:
            self.adjacency_list[source].append(destination)
    
    def depth_first_search(self, start_node):
        if start_node < 0 or start_node >= self.vertices:
            return []
        
        result = []
        visited = [False] * self.vertices
        self._dfs_util(start_node, visited, result)
        return result
    
    def _dfs_util(self, node, visited, result):
        visited[node] = True
        result.append(node)
        
        for neighbor in self.adjacency_list[node]:
            if not visited[neighbor]:
                self._dfs_util(neighbor, visited, result)


def main():
    # Test Case 1: Simple linear graph
    print("Test Case 1: Linear Graph")
    graph1 = Graph(5)
    graph1.add_edge(0, 1)
    graph1.add_edge(1, 2)
    graph1.add_edge(2, 3)
    graph1.add_edge(3, 4)
    print(f"DFS from node 0: {graph1.depth_first_search(0)}")
    
    # Test Case 2: Graph with branches
    print("\\nTest Case 2: Branched Graph")
    graph2 = Graph(7)
    graph2.add_edge(0, 1)
    graph2.add_edge(0, 2)
    graph2.add_edge(1, 3)
    graph2.add_edge(1, 4)
    graph2.add_edge(2, 5)
    graph2.add_edge(2, 6)
    print(f"DFS from node 0: {graph2.depth_first_search(0)}")
    
    # Test Case 3: Graph with cycle
    print("\\nTest Case 3: Graph with Cycle")
    graph3 = Graph(4)
    graph3.add_edge(0, 1)
    graph3.add_edge(1, 2)
    graph3.add_edge(2, 3)
    graph3.add_edge(3, 1)
    print(f"DFS from node 0: {graph3.depth_first_search(0)}")
    
    # Test Case 4: Disconnected graph
    print("\\nTest Case 4: Disconnected Graph")
    graph4 = Graph(6)
    graph4.add_edge(0, 1)
    graph4.add_edge(1, 2)
    graph4.add_edge(3, 4)
    graph4.add_edge(4, 5)
    print(f"DFS from node 0: {graph4.depth_first_search(0)}")
    print(f"DFS from node 3: {graph4.depth_first_search(3)}")
    
    # Test Case 5: Single node
    print("\\nTest Case 5: Single Node")
    graph5 = Graph(1)
    print(f"DFS from node 0: {graph5.depth_first_search(0)}")


if __name__ == "__main__":
    main()
