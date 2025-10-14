from collections import defaultdict
from typing import Dict, List, Tuple

def reparent_tree(adjacency_list: Dict[int, List[int]], new_root: int) -> Dict[int, List[int]]:
    """
    Reparents a tree on the given new_root node.

    :param adjacency_list: An adjacency list representing the undirected tree.
    :param new_root: The ID of the node to become the new root.
    :return: A dictionary representing the new directed tree (parent -> children),
             ordered by a pre-order traversal from the new root.
    """
    new_tree = {}  # In Python 3.7+, dicts preserve insertion order.

    def build_new_tree_dfs(current_node, parent_node):
        new_tree[current_node] = []
        
        # Get neighbors and sort for deterministic output
        neighbors = sorted(adjacency_list.get(current_node, []))
        
        for neighbor in neighbors:
            if neighbor != parent_node:
                new_tree[current_node].append(neighbor)
                build_new_tree_dfs(neighbor, current_node)

    build_new_tree_dfs(new_root, -1)  # Use -1 as a virtual parent for the root
    return new_tree

# --- Test Cases ---
def build_adj_list(edges: List[Tuple[int, int]]) -> Dict[int, List[int]]:
    adj = defaultdict(list)
    nodes = set()
    for u, v in edges:
        nodes.add(u)
        nodes.add(v)
    for u, v in edges:
        adj[u].append(v)
        adj[v].append(u)
    # Ensure all nodes exist as keys
    for node in nodes:
        if node not in adj:
            adj[node] = []
    return dict(adj)

def main():
    test_cases = [
        {
            "name": "Example from prompt",
            "edges": [(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (2, 6), (2, 7), (3, 8), (3, 9)],
            "new_root": 6
        },
        {
            "name": "Simple line graph",
            "edges": [(0, 1), (1, 2), (2, 3), (3, 4)],
            "new_root": 2
        },
        {
            "name": "Star graph, reparent on root",
            "edges": [(0, 1), (0, 2), (0, 3), (0, 4)],
            "new_root": 0
        },
        {
            "name": "Star graph, reparent on a leaf",
            "edges": [(0, 1), (0, 2), (0, 3), (0, 4)],
            "new_root": 3
        },
        {
            "name": "A more complex tree",
            "edges": [(1, 2), (1, 3), (1, 4), (2, 5), (2, 6), (4, 7), (4, 8)],
            "new_root": 4
        }
    ]

    for i, tc in enumerate(test_cases):
        print(f"--- Test Case {i+1}: {tc['name']} ---")
        adj_list = build_adj_list(tc['edges'])
        print(f"Reparenting on node: {tc['new_root']}")
        
        reparented_tree = reparent_tree(adj_list, tc['new_root'])
        print("Reparented Tree (Parent -> Children):")
        for key, value in reparented_tree.items():
            print(f"  {key}: {value}")
        print()

if __name__ == "__main__":
    main()