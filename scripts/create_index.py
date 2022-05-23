# create index for all my binaries

import hashlib
import os
import sys
import lief
import csv
import tqdm
import argparse

# parse the arguments
argp = argparse.ArgumentParser()
argp.add_argument("folder", type=str, default=".", help = "target folder")
argp.add_argument("index_path", type=str, default="index.csv", help="index file path")
argp.add_argument("--skip-dup-file", action='store_true', help = "skip duplicate files")
args = argp.parse_args()


hash_set = set()
path_set = set()

# rebuild index
index_path = args.index_path
if os.path.exists(index_path):
    with open(index_path, "r") as csvfile:
        index_reader = csv.DictReader(csvfile)
        for row in index_reader:
            path_set.add(row['filename'])

has_header = False
with open(index_path, 'r') as rfile:
    if rfile.readline().startswith("filename"):
        has_header = True
# append index
with open(index_path, "a") as csvfile:
    index_writer = csv.DictWriter(csvfile, fieldnames=["filename", "sha256", "md5"])
    if len(path_set) == 0 and not has_header:
        index_writer.writeheader()
    file_cnt = 0
    for root, _, files in os.walk(args.folder):
        for f in files:
            file_cnt += 1
    print("total files: %d" % file_cnt)
    tq = tqdm.tqdm(total=file_cnt, ascii=True)
    for root, _, files in os.walk(sys.argv[1]):
        for file in files:
            tq.update(1)
            fpath = os.path.join(root, file)
            fpath = os.path.abspath(fpath)
            if fpath in path_set and args.skip_dup_file:
                continue
            if lief.is_pe(fpath):
                sha256_hash = hashlib.sha256()
                md5_hash = hashlib.md5()
                with open(fpath, 'rb') as f:
                    for block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(block)
                        md5_hash.update(block)
                sha256_s = sha256_hash.hexdigest()
                md5_s = md5_hash.hexdigest()
                if sha256_s in hash_set:
                    continue
                hash_set.add(sha256_s)
                path_set.add(fpath)
                index_writer.writerow({"filename": fpath, "sha256": sha256_s, "md5": md5_s})
