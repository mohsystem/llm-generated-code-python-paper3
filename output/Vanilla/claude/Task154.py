
class Graph:
    def __init__(self, vertices):
        self.vertices = vertices
        self.adj_list = [[] for _ in range(vertices)]
    
    def add_edge(self, src, dest):
        self.adj_list[src].append(dest)
    
    def dfs(self, start_node):
        result = []
        visited = [False] * self.vertices
        self._dfs_util(start_node, visited, result)
        return result
    
    def _dfs_util(self, node, visited, result):
        visited[node] = True
        result.append(node)
        
        for neighbor in self.adj_list[node]:
            if not visited[neighbor]:
                self._dfs_util(neighbor, visited, result)


def main():
    # Test Case 1: Simple linear graph
    print("Test Case 1: Linear Graph (0->1->2->3)")
    g1 = Graph(4)
    g1.add_edge(0, 1)
    g1.add_edge(1, 2)
    g1.add_edge(2, 3)
    print(f"DFS from node 0: {g1.dfs(0)}")
    
    # Test Case 2: Graph with branching
    print("\\nTest Case 2: Branching Graph")
    g2 = Graph(7)
    g2.add_edge(0, 1)
    g2.add_edge(0, 2)
    g2.add_edge(1, 3)
    g2.add_edge(1, 4)
    g2.add_edge(2, 5)
    g2.add_edge(2, 6)
    print(f"DFS from node 0: {g2.dfs(0)}")
    
    # Test Case 3: Graph with cycle
    print("\\nTest Case 3: Graph with Cycle")
    g3 = Graph(4)
    g3.add_edge(0, 1)
    g3.add_edge(1, 2)
    g3.add_edge(2, 0)
    g3.add_edge(2, 3)
    print(f"DFS from node 0: {g3.dfs(0)}")
    
    # Test Case 4: Disconnected graph
    print("\\nTest Case 4: Disconnected Graph")
    g4 = Graph(5)
    g4.add_edge(0, 1)
    g4.add_edge(1, 2)
    g4.add_edge(3, 4)
    print(f"DFS from node 0: {g4.dfs(0)}")
    print(f"DFS from node 3: {g4.dfs(3)}")
    
    # Test Case 5: Single node
    print("\\nTest Case 5: Single Node")
    g5 = Graph(1)
    print(f"DFS from node 0: {g5.dfs(0)}")


if __name__ == "__main__":
    main()
