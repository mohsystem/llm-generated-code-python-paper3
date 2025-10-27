class Lse122:
    @staticmethod
    def do_memory_ops(data):
        SIZE = 10
        first = bytearray(SIZE)
        if data is not None:
            for i in range(min(SIZE, len(data))):
                first[i] = data[i] & 0xFF

        second = bytearray(SIZE)
        second[:] = first

        total = sum(second)

        del first  # free first chunk
        del second # free second chunk

        return total

if __name__ == "__main__":
    print(Lse122.do_memory_ops([0,1,2,3,4,5,6,7,8,9]))                 # 45
    print(Lse122.do_memory_ops([1]*10))                                 # 10
    print(Lse122.do_memory_ops([10,11,12,13,14,15,16,17,18,19]))        # 145
    print(Lse122.do_memory_ops([255]*10))                               # 2550
    print(Lse122.do_memory_ops([5,4,3,2,1,0,250,251,252,253]))          # 1021