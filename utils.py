def get_bit(val: int, pos: int) -> int:
    return (val >> pos) & 1

def get_bits(val: int, pos: int) -> int:
    mask = 1 << pos
    b = val >> pos
    return b & mask