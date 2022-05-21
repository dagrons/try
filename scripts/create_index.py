# create index for all my binaries

import hashlib
import os
import sys
import lief
import csv
import tqdm

with open("index.csv", "w") as csvfile:
    index_writer = csv.DictWriter(csvfile, fieldnames=["filename", "sha256", "md5"])
    index_writer.writeheader()
    fcnt = 0
    hashset = set()
    for root, _, files in os.walk(sys.argv[1]):
        for f in files:
            fcnt += 1
    print("total files: %d" % (fcnt))
    tq = tqdm.tqdm(total=fcnt, ascii=True)
    for root, _, files in os.walk(sys.argv[1]):
        for file in files:
            tq.update(1)
            fpath = os.path.join(root, file)
            fpath = os.path.abspath(fpath)
            if lief.is_pe(fpath):
                sha256_hash = hashlib.sha256()
                md5_hash = hashlib.md5()
                with open(fpath, 'rb') as f:
                    for block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(block)
                        md5_hash.update(block)
                sha256_s = sha256_hash.hexdigest()
                md5_s = md5_hash.hexdigest()
                if sha256_s in hashset:
                    continue
                hashset.add(sha256_s)
                index_writer.writerow({"filename": fpath, "sha256": sha256_s, "md5": md5_s})
