
from typing import Dict, List, Set


class Tree:
    def __init__(self, adjacency_list: Dict[int, List[int]]):
        if adjacency_list is None:
            raise ValueError("Adjacency list cannot be None")
        self.adjacency_list: Dict[int, List[int]] = {}
        for key, value in adjacency_list.items():
            if key is None or value is None:
                raise ValueError("None keys or values not allowed")
            if not isinstance(key, int):
                raise TypeError("Keys must be integers")
            self.adjacency_list[key] = list(value)
    
    def reparent(self, new_root: int) -> 'Tree':
        if not isinstance(new_root, int):
            raise TypeError("Root must be an integer")
        if new_root not in self.adjacency_list:
            raise ValueError("Node not in tree")
        
        new_adjacency_list: Dict[int, List[int]] = {}
        visited: Set[int] = set()
        
        self._build_reparented_tree(new_root, -1, visited, new_adjacency_list)
        
        return Tree(new_adjacency_list)
    
    def _build_reparented_tree(self, current: int, parent: int, 
                              visited: Set[int], 
                              new_adjacency_list: Dict[int, List[int]]) -> None:
        if current in visited:
            return
        visited.add(current)
        
        if current not in new_adjacency_list:
            new_adjacency_list[current] = []
        
        neighbors = self.adjacency_list.get(current, [])
        for neighbor in neighbors:
            if neighbor != parent and neighbor not in visited:
                new_adjacency_list[current].append(neighbor)
                self._build_reparented_tree(neighbor, current, visited, new_adjacency_list)
    
    def get_adjacency_list(self) -> Dict[int, List[int]]:
        return {key: list(value) for key, value in self.adjacency_list.items()}


def main():
    # Test case 1: Simple tree reparenting
    tree1 = {
        0: [1, 2, 3],
        1: [0, 4, 5],
        2: [0, 6, 7],
        3: [0, 8, 9],
        4: [1],
        5: [1],
        6: [2],
        7: [2],
        8: [3],
        9: [3]
    }
    t1 = Tree(tree1)
    reparented1 = t1.reparent(6)
    print(f"Test 1 - Reparent on 6: {reparented1.get_adjacency_list()}")
    
    # Test case 2: Single node
    tree2 = {0: []}
    t2 = Tree(tree2)
    reparented2 = t2.reparent(0)
    print(f"Test 2 - Single node: {reparented2.get_adjacency_list()}")
    
    # Test case 3: Linear tree
    tree3 = {
        0: [1],
        1: [0, 2],
        2: [1]
    }
    t3 = Tree(tree3)
    reparented3 = t3.reparent(2)
    print(f"Test 3 - Linear tree reparent on 2: {reparented3.get_adjacency_list()}")
    
    # Test case 4: Reparent on original root
    reparented4 = t1.reparent(0)
    print(f"Test 4 - Reparent on original root: {reparented4.get_adjacency_list()}")
    
    # Test case 5: Small tree
    tree5 = {
        0: [1, 2],
        1: [0],
        2: [0]
    }
    t5 = Tree(tree5)
    reparented5 = t5.reparent(1)
    print(f"Test 5 - Small tree reparent on 1: {reparented5.get_adjacency_list()}")


if __name__ == "__main__":
    main()
