import heapq
import sys

def dijkstra(graph, num_nodes, start_node):
    """
    Finds the shortest paths from a starting node to all other nodes in a weighted graph
    using Dijkstra's algorithm.
    
    Args:
        graph (list of lists of tuples): Adjacency list representation of the graph.
                                         graph[u] contains a list of (v, weight) tuples.
        num_nodes (int): The total number of nodes in the graph, indexed 0 to num_nodes-1.
        start_node (int): The starting node.
        
    Returns:
        list: A list of shortest distances from the start node. 'inf' for unreachable nodes.
        
    Raises:
        ValueError: If the input is invalid or the graph contains a negative edge weight.
    """
    # Input validation
    if not isinstance(graph, list) or num_nodes <= 0 or not (0 <= start_node < num_nodes):
        raise ValueError("Invalid input for Dijkstra's algorithm.")

    distances = [float('inf')] * num_nodes
    distances[start_node] = 0
    
    # Priority queue stores tuples of (distance, vertex)
    pq = [(0, start_node)]

    while pq:
        current_dist, u = heapq.heappop(pq)
        
        # If we've found a shorter path already, skip
        if current_dist > distances[u]:
            continue
            
        for v, weight in graph[u]:
            # Security check: Dijkstra's does not support negative weights
            if weight < 0:
                raise ValueError("Graph contains a negative edge weight.")
            
            # Relaxation step: if a shorter path to v is found through u
            # Python's integers handle arbitrary size, so overflow is not an issue
            new_dist = distances[u] + weight
            if new_dist < distances[v]:
                distances[v] = new_dist
                heapq.heappush(pq, (new_dist, v))
                
    return distances

def run_test(graph, num_nodes, start_node, test_case_num):
    print(f"\nTest Case {test_case_num}:")
    try:
        distances = dijkstra(graph, num_nodes, start_node)
        print(f"Shortest distances from node {start_node}:")
        for i, dist in enumerate(distances):
            print(f"  to node {i}: {dist if dist != float('inf') else 'Infinity'}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == '__main__':
    print("Python Dijkstra's Algorithm Test Cases:")

    # Test Case 1: Simple graph
    num_nodes1 = 5
    adj1 = [[] for _ in range(num_nodes1)]
    adj1[0].extend([(1, 10), (4, 3)])
    adj1[1].append((2, 2))
    adj1[2].append((3, 9))
    adj1[4].extend([(1, 4), (2, 8), (3, 2)])
    run_test(adj1, num_nodes1, 0, 1)

    # Test Case 2: Disconnected graph
    num_nodes2 = 5
    adj2 = [[] for _ in range(num_nodes2)]
    adj2[0].append((1, 1))
    adj2[1].append((0, 1))
    adj2[2].append((3, 2))
    adj2[3].append((2, 2))
    run_test(adj2, num_nodes2, 0, 2)
    
    # Test Case 3: Linear graph
    num_nodes3 = 4
    adj3 = [[] for _ in range(num_nodes3)]
    adj3[0].append((1, 5))
    adj3[1].append((2, 5))
    adj3[2].append((3, 5))
    run_test(adj3, num_nodes3, 0, 3)

    # Test Case 4: Graph with a cycle
    num_nodes4 = 4
    adj4 = [[] for _ in range(num_nodes4)]
    adj4[0].append((1, 1))
    adj4[1].extend([(2, 2), (3, 4)])
    adj4[2].append((0, 3)) # Cycle back to start
    run_test(adj4, num_nodes4, 0, 4)

    # Test Case 5: Start node with no outgoing edges
    num_nodes5 = 3
    adj5 = [[] for _ in range(num_nodes5)]
    adj5[1].append((2, 10))
    run_test(adj5, num_nodes5, 0, 5)