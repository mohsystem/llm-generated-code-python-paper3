import math

def compute_area(radius: float) -> float:
    return math.pi * radius * radius

if __name__ == "__main__":
    radii = [0.0, 1.0, 2.5, 10.0, 123.456]
    for r in radii:
        area = compute_area(r)
        print(f"Radius: {r:.6f} -> Area: {area:.6f}")