import collections

# This is a mock implementation for testing purposes.
class Master:
    def __init__(self, secret: str, words: list[str], allowed_guesses: int):
        self._secret = secret
        self._word_set = set(words)
        self.guesses = 0
        self.allowed_guesses = allowed_guesses
        self.found = False

    def guess(self, word: str) -> int:
        print(f"Guessing: {word}")
        self.guesses += 1
        if self.guesses > self.allowed_guesses:
            print("Exceeded allowed guesses!")
        if word not in self._word_set:
            return -1
        if word == self._secret:
            self.found = True
        return sum(c1 == c2 for c1, c2 in zip(self._secret, word))

    def print_result(self):
        if self.found and self.guesses <= self.allowed_guesses:
            print("You guessed the secret word correctly.")
        else:
            print("Either you took too many guesses, or you did not find the secret word.")


class Task194:
    def findSecretWord(self, words: list[str], master: 'Master') -> None:
        def count_matches(w1, w2):
            return sum(c1 == c2 for c1, c2 in zip(w1, w2))

        candidates = list(words)
        
        for _ in range(30): # Max allowed guesses from constraints
            if not candidates:
                break
            
            # Find best guess using minimax strategy
            if len(candidates) <= 2:
                best_guess = candidates[0]
            else:
                min_max_partition_size = float('inf')
                best_guess = ""
                for guess in words:
                    partitions = collections.defaultdict(int)
                    for cand in candidates:
                        partitions[count_matches(guess, cand)] += 1
                    
                    max_partition_size = max(partitions.values())
                    if max_partition_size < min_max_partition_size:
                        min_max_partition_size = max_partition_size
                        best_guess = guess

            matches = master.guess(best_guess)
            if matches == 6:
                return

            candidates = [word for word in candidates if count_matches(best_guess, word) == matches]

if __name__ == '__main__':
    solution = Task194()
    
    # Test Case 1
    print("--- Test Case 1 ---")
    words1 = ["acckzz", "ccbazz", "eiowzz", "abcczz"]
    master1 = Master("acckzz", words1, 10)
    solution.findSecretWord(words1, master1)
    master1.print_result()
    
    # Test Case 2
    print("\n--- Test Case 2 ---")
    words2 = ["hamada", "khaled"]
    master2 = Master("hamada", words2, 10)
    solution.findSecretWord(words2, master2)
    master2.print_result()
    
    # Test Case 3
    print("\n--- Test Case 3 ---")
    words3 = ["wichbx","oahwep","tpulot","eqznrt","vjhszz","pcmatp","xqmsgr",
              "bnrhml","ccoyyo","ajcwbj","arwfnl","nafmtm","xoaumd","vbejda",
              "kaefne","swcrkh","reeyhj","vmcwaf","chxitv","qkwjna","vklpkp",
              "xfnayl","ktgmfn","xrmzzm","fgtuki","zcffuv","srxuus","pydgmq"]
    master3 = Master("ccoyyo", words3, 15)
    solution.findSecretWord(words3, master3)
    master3.print_result()
    
    # Test Case 4
    print("\n--- Test Case 4 ---")
    words4 = ["aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee", "ffffff"]
    master4 = Master("aaaaaa", words4, 10)
    solution.findSecretWord(words4, master4)
    master4.print_result()

    # Test Case 5
    print("\n--- Test Case 5 ---")
    words5 = ["abacac", "abadaf", "adafac", "afacab"]
    master5 = Master("abacac", words5, 10)
    solution.findSecretWord(words5, master5)
    master5.print_result()