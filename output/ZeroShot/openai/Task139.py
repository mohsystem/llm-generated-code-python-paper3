import math
import sys

def compute_circle_area(radius):
    try:
        r = float(radius)
    except (TypeError, ValueError):
        raise ValueError("Radius must be a real number.")
    if not math.isfinite(r):
        raise ValueError("Radius must be finite.")
    if r < 0.0:
        raise ValueError("Radius must be non-negative.")
    threshold = math.sqrt(sys.float_info.max / math.pi)
    if r > threshold:
        return math.inf
    return math.pi * r * r

def main():
    tests = [0.0, 1.0, 2.5, 1e154, -3.0]
    for r in tests:
        try:
            area = compute_circle_area(r)
            print(f"radius={r} area={area}")
        except ValueError as e:
            print(f"radius={r} error={e}")

if __name__ == "__main__":
    main()