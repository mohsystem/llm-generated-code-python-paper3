from typing import List, Set

class Graph:
    """
    Implements a directed graph and provides a DFS traversal method.
    """
    def __init__(self, vertices: int):
        if vertices < 0:
            raise ValueError("Number of vertices must be non-negative")
        self.V = vertices
        self.adj = [[] for _ in range(vertices)]

    def add_edge(self, u: int, v: int) -> None:
        """Adds an edge from vertex u to vertex v."""
        if 0 <= u < self.V and 0 <= v < self.V:
            self.adj[u].append(v)
        else:
            print(f"Error: Vertex out of bounds. Cannot add edge ({u}, {v})")

    def _dfs_util(self, v: int, visited: Set[int], result: List[int]) -> None:
        """Recursive utility for DFS."""
        visited.add(v)
        result.append(v)
        for neighbour in self.adj[v]:
            if neighbour not in visited:
                self._dfs_util(neighbour, visited, result)

    def dfs(self, start_node: int) -> List[int]:
        """
        Performs a Depth-First Search traversal starting from a given node.
        
        Args:
            start_node: The node to start the traversal from.
            
        Returns:
            A list of integers representing the DFS traversal path.
        """
        if not (0 <= start_node < self.V):
            print(f"Error: Start node {start_node} is invalid.")
            return []
        
        visited: Set[int] = set()
        result: List[int] = []
        self._dfs_util(start_node, visited, result)
        return result

def main():
    """Main function with test cases for DFS."""
    # Test Case 1: Standard DFS
    print("Test Case 1:")
    g1 = Graph(7)
    g1.add_edge(0, 1)
    g1.add_edge(0, 2)
    g1.add_edge(1, 3)
    g1.add_edge(1, 4)
    g1.add_edge(2, 5)
    g1.add_edge(2, 6)
    print(f"DFS starting from vertex 0: {g1.dfs(0)}")

    # Test Case 2: Graph with a cycle
    print("\nTest Case 2:")
    g2 = Graph(4)
    g2.add_edge(0, 1)
    g2.add_edge(0, 2)
    g2.add_edge(1, 2)
    g2.add_edge(2, 0)
    g2.add_edge(2, 3)
    g2.add_edge(3, 3)
    print(f"DFS starting from vertex 2: {g2.dfs(2)}")

    # Test Case 3: Disconnected graph component
    print("\nTest Case 3:")
    g3 = Graph(5)
    g3.add_edge(0, 1)
    g3.add_edge(1, 2)
    g3.add_edge(3, 4)
    print(f"DFS starting from vertex 0: {g3.dfs(0)}")
    print(f"DFS starting from vertex 3: {g3.dfs(3)}")

    # Test Case 4: Start node has no outgoing edges
    print("\nTest Case 4:")
    g4 = Graph(3)
    g4.add_edge(0, 1)
    g4.add_edge(0, 2)
    print(f"DFS starting from vertex 1: {g4.dfs(1)}")

    # Test Case 5: Invalid start node
    print("\nTest Case 5:")
    g5 = Graph(3)
    g5.add_edge(0, 1)
    g5.add_edge(1, 2)
    print(f"DFS starting from vertex 5: {g5.dfs(5)}")
    print(f"DFS starting from vertex -1: {g5.dfs(-1)}")

if __name__ == "__main__":
    main()