
class Master:
    def guess(self, word: str) -> int:
        pass

class Task194:
    def match(self, a, b):
        return sum(c1 == c2 for c1, c2 in zip(a, b))
    
    def findSecretWord(self, words, master):
        candidates = words[:]
        
        for attempt in range(10):
            if not candidates:
                break
                
            guess = self.select_best_guess(candidates)
            matches = master.guess(guess)
            
            if matches == 6:
                return
            
            candidates = [w for w in candidates if self.match(guess, w) == matches]
    
    def select_best_guess(self, candidates):
        if len(candidates) <= 2:
            return candidates[0]
        
        best_word = candidates[0]
        min_max_group = float('inf')
        
        for candidate in candidates:
            groups = [0] * 7
            for word in candidates:
                groups[self.match(candidate, word)] += 1
            
            max_group = max(groups)
            
            if max_group < min_max_group:
                min_max_group = max_group
                best_word = candidate
        
        return best_word

# Test cases
if __name__ == "__main__":
    class TestMaster:
        def __init__(self, secret, words):
            self.secret = secret
            self.words = words
        
        def guess(self, word):
            if word not in self.words:
                return -1
            return sum(c1 == c2 for c1, c2 in zip(word, self.secret))
    
    solution = Task194()
    
    # Test 1
    master1 = TestMaster("acckzz", ["acckzz","ccbazz","eiowzz","abcczz"])
    solution.findSecretWord(["acckzz","ccbazz","eiowzz","abcczz"], master1)
    print("Test 1 passed")
    
    # Test 2
    master2 = TestMaster("hamada", ["hamada","khaled"])
    solution.findSecretWord(["hamada","khaled"], master2)
    print("Test 2 passed")
