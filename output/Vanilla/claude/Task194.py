
class Master:
    def guess(self, word):
        pass

class Task194:
    def findSecretWord(self, words, master):
        candidates = list(words)
        
        for _ in range(10):
            if not candidates:
                break
            
            guess = self.get_best_guess(candidates)
            matches = master.guess(guess)
            
            if matches == 6:
                return
            
            candidates = self.filter_candidates(candidates, guess, matches)
    
    def get_best_guess(self, candidates):
        best_word = candidates[0]
        min_max_group = float('inf')
        
        for word in candidates:
            match_counts = [0] * 7
            for candidate in candidates:
                matches = self.count_matches(word, candidate)
                match_counts[matches] += 1
            
            max_group = max(match_counts)
            
            if max_group < min_max_group:
                min_max_group = max_group
                best_word = word
        
        return best_word
    
    def filter_candidates(self, candidates, guess, target_matches):
        return [word for word in candidates if self.count_matches(word, guess) == target_matches]
    
    def count_matches(self, a, b):
        return sum(1 for i in range(6) if a[i] == b[i])

# Test cases
def main():
    solution = Task194()
    
    # Test 1
    class Master1:
        def __init__(self):
            self.secret = "acckzz"
        def guess(self, word):
            if word not in ["acckzz","ccbazz","eiowzz","abcczz"]:
                return -1
            return sum(1 for i in range(6) if word[i] == self.secret[i])
    
    master1 = Master1()
    solution.findSecretWord(["acckzz","ccbazz","eiowzz","abcczz"], master1)
    print("Test 1 completed")
    
    # Test 2
    class Master2:
        def __init__(self):
            self.secret = "hamada"
        def guess(self, word):
            if word not in ["hamada","khaled"]:
                return -1
            return sum(1 for i in range(6) if word[i] == self.secret[i])
    
    master2 = Master2()
    solution.findSecretWord(["hamada","khaled"], master2)
    print("Test 2 completed")

if __name__ == "__main__":
    main()
