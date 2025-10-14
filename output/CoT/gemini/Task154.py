from collections import defaultdict

class Graph:
    def __init__(self):
        # Using defaultdict to store the graph (adjacency list)
        self.graph = defaultdict(list)

    def add_edge(self, u, v):
        """Adds an undirected edge to the graph."""
        self.graph[u].append(v)
        self.graph[v].append(u)

    def _dfs_util(self, v, visited, result):
        """A recursive utility function for DFS."""
        # Mark the current node as visited and add it to the result
        visited.add(v)
        result.append(v)

        # Recur for all the vertices adjacent to this vertex
        for neighbour in self.graph[v]:
            if neighbour not in visited:
                self._dfs_util(neighbour, visited, result)

    def dfs(self, start_node):
        """
        Performs DFS traversal starting from a given node.
        Returns a list of nodes in DFS order.
        """
        if start_node not in self.graph:
            print(f"Error: Start node {start_node} not in graph.")
            return []
            
        visited = set()
        result = []
        
        # Call the recursive helper function to store DFS traversal
        self._dfs_util(start_node, visited, result)
        return result

# Main execution block
if __name__ == "__main__":
    g = Graph()

    # Create a sample graph
    g.add_edge(0, 1)
    g.add_edge(0, 2)
    g.add_edge(1, 3)
    g.add_edge(1, 4)
    g.add_edge(2, 5)
    g.add_edge(2, 6)
    g.add_edge(3, 7)
    # Node 7 is connected to 3

    print("Depth First Traversal (starting from various nodes):")

    # Test Case 1
    start_node1 = 0
    print(f"Test Case 1 (Start from {start_node1}): {g.dfs(start_node1)}")

    # Test Case 2
    start_node2 = 3
    print(f"Test Case 2 (Start from {start_node2}): {g.dfs(start_node2)}")

    # Test Case 3
    start_node3 = 2
    print(f"Test Case 3 (Start from {start_node3}): {g.dfs(start_node3)}")

    # Test Case 4
    start_node4 = 6
    print(f"Test Case 4 (Start from {start_node4}): {g.dfs(start_node4)}")

    # Test Case 5
    start_node5 = 5
    print(f"Test Case 5 (Start from {start_node5}): {g.dfs(start_node5)}")