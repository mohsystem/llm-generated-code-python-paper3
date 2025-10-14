
class Master:
    def guess(self, word: str) -> int:
        pass

class Task194:
    def count_matches(self, a: str, b: str) -> int:
        return sum(c1 == c2 for c1, c2 in zip(a, b))
    
    def findSecretWord(self, words: list, master: Master) -> None:
        candidates = words[:]
        
        for _ in range(10):
            if not candidates:
                break
            
            # Pick the word that minimizes the maximum group size
            guess = candidates[0]
            min_max_group = float('inf')
            
            for candidate in candidates:
                groups = {}
                for word in candidates:
                    matches = self.count_matches(candidate, word)
                    groups[matches] = groups.get(matches, 0) + 1
                max_group = max(groups.values())
                if max_group < min_max_group:
                    min_max_group = max_group
                    guess = candidate
            
            matches = master.guess(guess)
            if matches == 6:
                return
            
            # Filter candidates based on matches
            candidates = [word for word in candidates 
                         if self.count_matches(guess, word) == matches]

# Test cases
if __name__ == "__main__":
    solution = Task194()
    print("Test 1: Expected to find 'acckzz'")
    print("Test 2: Expected to find 'hamada'")
