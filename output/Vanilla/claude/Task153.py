
from collections import deque

class Graph:
    def __init__(self, vertices):
        self.vertices = vertices
        self.adjacency_list = [[] for _ in range(vertices)]
    
    def add_edge(self, source, destination):
        self.adjacency_list[source].append(destination)
    
    def bfs(self, start_node):
        result = []
        visited = [False] * self.vertices
        queue = deque()
        
        visited[start_node] = True
        queue.append(start_node)
        
        while queue:
            current = queue.popleft()
            result.append(current)
            
            for neighbor in self.adjacency_list[current]:
                if not visited[neighbor]:
                    visited[neighbor] = True
                    queue.append(neighbor)
        
        return result

def breadth_first_search(vertices, edges, start_node):
    graph = Graph(vertices)
    for edge in edges:
        graph.add_edge(edge[0], edge[1])
    return graph.bfs(start_node)

if __name__ == "__main__":
    # Test Case 1: Simple linear graph
    print("Test Case 1:")
    edges1 = [[0, 1], [1, 2], [2, 3]]
    print(breadth_first_search(4, edges1, 0))
    
    # Test Case 2: Graph with multiple branches
    print("\\nTest Case 2:")
    edges2 = [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5]]
    print(breadth_first_search(6, edges2, 0))
    
    # Test Case 3: Disconnected graph
    print("\\nTest Case 3:")
    edges3 = [[0, 1], [2, 3]]
    print(breadth_first_search(4, edges3, 0))
    
    # Test Case 4: Graph with cycles
    print("\\nTest Case 4:")
    edges4 = [[0, 1], [0, 2], [1, 2], [2, 0], [2, 3]]
    print(breadth_first_search(4, edges4, 0))
    
    # Test Case 5: Single node
    print("\\nTest Case 5:")
    edges5 = []
    print(breadth_first_search(1, edges5, 0))
