import collections
import random

# This is a TestMaster class to simulate the problem's environment for local testing.
class Master:
    def __init__(self, secret: str, words: list[str], allowedGuesses: int):
        self.secret = secret
        self.word_set = set(words)
        self.allowed_guesses = allowedGuesses
        self.guesses_made = 0
        self.found = False

    def guess(self, word: str) -> int:
        self.guesses_made += 1
        if word not in self.word_set:
            return -1
        
        matches = sum(c1 == c2 for c1, c2 in zip(word, self.secret))
        
        if matches == len(self.secret):
            self.found = True
            
        return matches

    def report(self):
        if self.found and self.guesses_made <= self.allowed_guesses:
            print("You guessed the secret word correctly.")
        else:
            print("Either you took too many guesses, or you did not find the secret word.")
        print(f"Guesses made: {self.guesses_made}")

# Solution function
def findSecretWord(words: list[str], master: 'Master'):
    """
    Finds the secret word using a minimax strategy.
    :param words: The list of possible words.
    :param master: The master object to make guesses with.
    """
    def match(w1, w2):
        return sum(c1 == c2 for c1, c2 in zip(w1, w2))

    # Use a mutable list for candidates, which will be pruned.
    candidates = list(words)
    # The problem constraints state allowedGuesses is at most 30.
    for _ in range(30):
        if not candidates:
            break

        # Minimax: Choose a word from candidates that minimizes the size
        # of the largest remaining group of candidates.
        counts = collections.defaultdict(int)
        for w1 in candidates:
            groups = [0] * 7
            for w2 in candidates:
                groups[match(w1, w2)] += 1
            # The score for a word is the size of the largest group it creates.
            # We want to minimize this score.
            counts[w1] = max(groups)
        
        best_guess = min(candidates, key=lambda w: counts[w])
        
        # Make a guess with the best word found.
        matches = master.guess(best_guess)
        
        if matches == 6:
            return
            
        # Prune the candidate list based on the feedback.
        candidates = [word for word in candidates if match(best_guess, word) == matches]

# Main execution block for testing
if __name__ == "__main__":
    # Test Case 1
    print("Test Case 1:")
    words1 = ["acckzz", "ccbazz", "eiowzz", "abcczz"]
    secret1 = "acckzz"
    master1 = Master(secret1, words1, 10)
    findSecretWord(words1, master1)
    master1.report()

    # Test Case 2
    print("\nTest Case 2:")
    words2 = ["hamada", "khaled"]
    secret2 = "hamada"
    master2 = Master(secret2, words2, 10)
    findSecretWord(words2, master2)
    master2.report()

    # Test Case 3
    print("\nTest Case 3:")
    words3 = ["wichbx", "oahwep", "tpulot", "eqznzs", "vvmplb", "eywinm"]
    secret3 = "oahwep"
    master3 = Master(secret3, words3, 10)
    findSecretWord(words3, master3)
    master3.report()

    # Test Case 4
    print("\nTest Case 4:")
    words4 = ["hbaczn", "aqqbxu", "ajasjw", "rdexkw", "fcceuc", "pcblmb", "bcckqc", "ccbzzw", "agagxt", "ccbazy"]
    secret4 = "hbaczn"
    master4 = Master(secret4, words4, 10)
    findSecretWord(words4, master4)
    master4.report()

    # Test Case 5
    print("\nTest Case 5:")
    words5 = ["aaaaaa", "bbbbbb", "cccccc"]
    secret5 = "bbbbbb"
    master5 = Master(secret5, words5, 10)
    findSecretWord(words5, master5)
    master5.report()