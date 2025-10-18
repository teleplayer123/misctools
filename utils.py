import ctypes
from typing import Type

CTYPE_VAR = Type[ctypes._SimpleCData] 

def get_bit(val: int, pos: int) -> int:
    return (val >> pos) & 1

def get_bits(val: int, pos: int) -> int:
    mask = 1 << pos
    b = val >> pos
    return b & mask

def set_ctype_buffer(buf: list, var_type: CTYPE_VAR) -> ctypes.Array:
    size = len(buf)
    c_arr = (var_type * size)(*buf)
    return c_arr

def carray_to_list(c_arr: ctypes.Array) -> list:
    return [c_arr[i] for i in range(len(c_arr))]

def carray_to_hex(c_arr: ctypes.Array) -> list:
    return [hex(b) for b in c_arr]