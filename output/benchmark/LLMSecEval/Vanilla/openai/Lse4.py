class Lse4:
    VEHICLES = ["Car", "Truck", "Bike", "Bus", "Van"]

    @staticmethod
    def get_vehicle(input_str: str) -> str:
        try:
            idx = int(input_str.strip())
            if 0 <= idx < len(Lse4.VEHICLES):
                return Lse4.VEHICLES[idx]
            return "Invalid index"
        except ValueError:
            return "Invalid integer"


if __name__ == "__main__":
    user_input = input("Enter index of vehicle: ")
    print(Lse4.get_vehicle(user_input))

    # 5 test cases
    tests = ["0", "1", "2", "3", "4"]
    for t in tests:
        print(f"Input: {t} -> {Lse4.get_vehicle(t)}")