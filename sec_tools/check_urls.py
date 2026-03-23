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
    """Check a file for URLs and return a tuple of (urls from text files, urls from binary files)"""
    # urls from text files
    urls_text = []
    # urls from binary files
    urls_bin = []

    try:
        with open(fp) as fh:
            for line in fh.readlines():
                url = URL_REGX.findall(line)
                if len(url) > 0:
                    urls_text.extend(url)
    except UnicodeDecodeError:
        with open(fp, "rb") as fh:
            for line in fh.readlines():
                try:
                    url = URL_DETAILED_REGX.findall(line.decode("utf-8"))
                    if len(url) > 0:
                        urls_bin.extend(url)
                except UnicodeDecodeError:
                    continue
    except Exception as err:
        print(f"Error processing {fp}: {err}")
    return urls_text, urls_bin

def main():
    urls_text_by_filename = {}
    urls_bin_by_filename = {}
    usage = f"{sys.argv[0]} <dirpath>"
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("path", nargs=1, help="path to directory")
    args = parser.parse_args()
    path = args.path[0]
    for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
            fp = os.path.join(dirpath, filename)
            if os.path.isfile(fp):
                urls_text, urls_bin = check_file_for_urls(fp)
                if len(urls_text) > 0:
                    urls_text_by_filename[fp] = urls_text
                if len(urls_bin) > 0:
                    urls_bin_by_filename[fp] = urls_bin
    return urls_text_by_filename, urls_bin_by_filename

if __name__ == "__main__":
    res_text, res_bin = main()
    print("\nDiscovered URLs (Text Files)")
    print("-----------------")
    pprint(res_text)
    print("\nDiscovered URLs (Binary Files)")
    print("-----------------")
    pprint(res_bin)