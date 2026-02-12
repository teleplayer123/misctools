import sys
from typing import Tuple, List

def get_chars(r: Tuple[int,int]) -> List[str]:
    chars = []
    for i in range(r[0],r[1]):
        chars.append(chr(i))
    return chars

def create_pattern(length: int):
    alphaUpper = get_chars((65, 91))
    alphaLowwer = get_chars((97, 123))
    nums = get_chars((48, 58))
    pattern = ""
    for i in range(len(alphaUpper)):
        if len(pattern) >= length:
            break
        for j in range(len(alphaLowwer)):
            if len(pattern) >= length:
                break
            for k in range(len(nums)):
                pattern += "%s%s%s" %(alphaUpper[i], alphaLowwer[j], nums[k])
                if len(pattern) >= length:
                    break
    if len(pattern) > length:
        trunc = len(pattern) - length
        pattern = pattern[:-trunc]
    return pattern

def pattern_offset(val, length):
    pattern = str(create_pattern(length))
    return pattern.index(str(val))

def main():
    if len(sys.argv) < 2:
        print("Usage: %s [length=int]" %sys.argv[0])
        sys.exit(0)
    length = int(sys.argv[1])
    pattern = create_pattern(length)
    print(pattern)

    partpat = input("Enter part of pattern to get offset: ")
    res = pattern_offset(partpat, length)
    return res

res = main()
print(res)