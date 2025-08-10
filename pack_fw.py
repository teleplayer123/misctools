import argparse
import os
import sys

class Part:
    def __init__(self, start_offset, end_offset, name):
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.name = name

    def align_data(self, data):
        if len(data) < self.end_offset:
            rem = self.end_offset - len(data)
            data = data + bytes(rem)
        return data

    def __str__(self):
        return \
        f"""
        {self.start_offset} - {self.end_offset}     {self.name}
        """
    
class PackFW:
    def __init__(self, csv_path, bin_dir, new_filename):
        self.bin_dir = bin_dir
        self.csv_path = csv_path
        self.new_filename = new_filename

    def parse_mtdparts(self):
        mtdparts = {}
        with open(self.csv_path) as fh:
            for line in fh.readlines():
                try:
                    start, end, name = line.split(",")
                    name = name.strip("\n")
                    start = int(start, 16)
                    end = int(end, 16)
                except ValueError:
                    print("Error: each line in CSV file must follow this format: int,int,str")
                    sys.exit()
                part_path = os.path.join(self.bin_dir, name)
                print(f"[*] Searching for binary at location {part_path}")
                if not os.stat(part_path):
                    print("Error: name at the end of each line must be name of the respective binary located in bin_dir")
                    sys.exit()
                p = Part(start, end, name)
                mtdparts[part_path] = p
                print(f"[+] found partition {str(p)}")
        return mtdparts
    
    def get_aligned_data(self, part, filename):
        with open(filename, "rb") as fh:
            data = fh.read()
        data = part.align_data(data)
        return data
    
    def write_fw(self):
        mtdparts = self.parse_mtdparts()
        with open(self.new_filename, "wb") as fh:
            for path, part in mtdparts.items():
                fh.seek(part.start_offset)
                data = self.get_aligned_data(part, path)
                fh.write(data)
        print(f"[+] firmware written to file {self.new_filename}")
                
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bindir", help="directory containing binary files to combine")
    parser.add_argument("csvpath", help="path to csv file describing the start and end offsets for each binary")
    parser.add_argument("--outfile", "-o", dest="outfile", type=str, default="output.bin", help="file name for new firmware file")
    args = parser.parse_args()

    bin_dir = args.bindir
    csv_path = args.csvpath
    outifle = args.outfile
    packer = PackFW(csv_path, bin_dir, outifle)

    packer.write_fw()

if __name__ == "__main__":
    main()