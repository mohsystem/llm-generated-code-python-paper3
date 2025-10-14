from collections import defaultdict

class Graph:
    """
    Class to represent a graph using an adjacency list.
    """
    def __init__(self, vertices):
        """
        Graph constructor.
        :param vertices: Number of vertices in the graph.
        """
        self.V = vertices
        self.graph = defaultdict(list)

    def add_edge(self, u, v):
        """
        Adds an edge to the graph.
        :param u: The source vertex.
        :param v: The destination vertex.
        """
        self.graph[u].append(v)

    def _dfs_util(self, v, visited, result):
        """
        A recursive helper function for DFS.
        :param v: The current vertex.
        :param visited: A set to keep track of visited vertices.
        :param result: The list to store the DFS traversal order.
        """
        visited.add(v)
        result.append(v)

        for neighbor in self.graph[v]:
            if neighbor not in visited:
                self._dfs_util(neighbor, visited, result)

    def perform_dfs(self, start_node):
        """
        Performs Depth First Search traversal starting from a given node.
        :param start_node: The starting node for the DFS.
        :return: A list of integers representing the DFS traversal.
        """
        if start_node >= self.V:
            print("Start node is out of bounds.")
            return []
            
        visited = set()
        result = []
        self._dfs_util(start_node, visited, result)
        return result

def main():
    # Test Case 1: Simple linear graph
    print("Test Case 1:")
    g1 = Graph(4)
    g1.add_edge(0, 1)
    g1.add_edge(1, 2)
    g1.add_edge(2, 3)
    print(f"DFS starting from node 0: {g1.perform_dfs(0)}")

    # Test Case 2: Graph with a fork
    print("\nTest Case 2:")
    g2 = Graph(5)
    g2.add_edge(0, 1)
    g2.add_edge(0, 2)
    g2.add_edge(1, 3)
    g2.add_edge(1, 4)
    print(f"DFS starting from node 0: {g2.perform_dfs(0)}")

    # Test Case 3: Graph with a cycle
    print("\nTest Case 3:")
    g3 = Graph(4)
    g3.add_edge(0, 1)
    g3.add_edge(1, 2)
    g3.add_edge(2, 0)
    g3.add_edge(2, 3)
    print(f"DFS starting from node 0: {g3.perform_dfs(0)}")

    # Test Case 4: Disconnected graph (DFS only visits connected component)
    print("\nTest Case 4:")
    g4 = Graph(5)
    g4.add_edge(0, 1)
    g4.add_edge(0, 2)
    g4.add_edge(3, 4)
    print(f"DFS starting from node 0: {g4.perform_dfs(0)}")
    print(f"DFS starting from node 3: {g4.perform_dfs(3)}")

    # Test Case 5: Single-node graph
    print("\nTest Case 5:")
    g5 = Graph(1)
    print(f"DFS starting from node 0: {g5.perform_dfs(0)}")

if __name__ == "__main__":
    main()