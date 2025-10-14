from decimal import Decimal, ROUND_HALF_UP, getcontext
import math

class Task167:
    @staticmethod
    def cubeDiagonal(volume: float) -> float:
        if not math.isfinite(volume) or volume < 0.0:
            return float('nan')
        diag = (volume ** (1.0 / 3.0)) * math.sqrt(3.0)
        getcontext().prec = 28
        rounded = Decimal(str(diag)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        return float(rounded)

if __name__ == "__main__":
    tests = [8.0, 343.0, 1157.625, 0.0, -5.0]
    for v in tests:
        res = Task167.cubeDiagonal(v)
        if math.isnan(res):
            print(f"cubeDiagonal({v}) = NaN")
        else:
            print(f"cubeDiagonal({v}) = {res:.2f}")