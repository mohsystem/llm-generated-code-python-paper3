import collections

class Graph:
    def __init__(self, vertices):
        self.V = vertices
        self.adj = collections.defaultdict(list)

    def add_edge(self, u, v):
        if 0 <= u < self.V and 0 <= v < self.V:
            self.adj[u].append(v)
            self.adj[v].append(u) # For undirected graph

    def bfs(self, start_node):
        """
        Performs Breadth-First Search traversal on the graph.
        :param start_node: The node to start the traversal from.
        :return: A list of nodes in the order they were visited.
        """
        result = []
        if not (0 <= start_node < self.V):
            print(f"Error: Start node {start_node} is out of bounds.")
            return result
            
        visited = [False] * self.V
        queue = collections.deque([start_node])
        visited[start_node] = True

        while queue:
            current_node = queue.popleft()
            result.append(current_node)

            for neighbor in self.adj[current_node]:
                if not visited[neighbor]:
                    visited[neighbor] = True
                    queue.append(neighbor)
        
        return result

def main():
    """Main function to run test cases."""
    print("--- Breadth-First Search (BFS) Traversal ---")
    
    # Graph structure for all test cases
    #        0
    #       / \
    #      1---2
    #     / \ |
    #    3---4 5
    #         |
    #         6
    num_vertices = 7
    g = Graph(num_vertices)
    g.add_edge(0, 1)
    g.add_edge(0, 2)
    g.add_edge(1, 3)
    g.add_edge(1, 4)
    g.add_edge(2, 5)
    g.add_edge(3, 4)
    g.add_edge(5, 6)
    
    start_nodes = [0, 3, 6, 4, 1]

    for i, start_node in enumerate(start_nodes):
        print(f"\nTest Case {i + 1}: Starting from node {start_node}")
        bfs_result = g.bfs(start_node)
        print(f"BFS Traversal: {' '.join(map(str, bfs_result))}")

if __name__ == "__main__":
    main()