import argparse
import os
from pprint import pprint
import re
import sys

# match all URLs simple
URL_REGX = re.compile(r"https?://[^\s]+")
# match URLs detailed
URL_DETAILED_REGX = re.compile(r"https?://[a-zA-Z0-9\.\-_]+(?:\:[0-9]+)?(?:/[^\s]*)?")

def check_file_for_urls(fp):
    urls = []
    try:
        with open(fp) as fh:
            for line in fh.readlines():
                url = URL_REGX.findall(line)
                if len(url) > 0:
                    urls.extend(url)
    except Exception as err:
        print(f"Error processing {fp}: {err}")
    return urls

def main():
    urls_by_filename = {}
    usage = f"{sys.argv[0]} <dirpath>"
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("path", nargs=1, help="path to directory")
    args = parser.parse_args()
    path = args.path[0]
    for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
            fp = os.path.join(dirpath, filename)
            if os.path.isfile(fp):
                urls = check_file_for_urls(fp)
                if len(urls) > 0:
                    urls_by_filename[fp] = urls
    return urls_by_filename

if __name__ == "__main__":
    res = main()
    print("\nDiscovered URLs")
    print("-----------------")
    pprint(res)