import sys
import re

def parse_uboot_dump(filename):
    start_line_regx = re.compile(r"^[0-9a-fA-F]{8}:\s")
    outfile = filename.replace(".log", ".bin")
    new_fh = open(outfile, "w+b")
    line_num = 1
    with open(filename, "r") as fh:
        for line in fh.readlines():
            print(f"processing line {line_num}")
            line_num += 1
            # check line starts with 64bit address
            if start_line_regx.match(line) == None:
                # skip garbage
                continue
            # strip ascii setion from line
            line = line.split("  ", maxsplit=1)[0]
            # break line on colon
            line = line.split(":", maxsplit=1)
            if len(line) < 2:
                # bad line, move on
                continue
            # remove space from isolated hex part of line
            hex_bytes = line[1].split(" ")
            for b in hex_bytes:
                data = bytes.fromhex(b)
                new_fh.write(data)
    new_fh.close()


def main():
    fname = sys.argv[1]
    parse_uboot_dump(fname)

if __name__ == "__main__":
    main()