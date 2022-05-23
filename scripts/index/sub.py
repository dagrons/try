"""c.csv = a.csv - b.csv"""

import argparse
import csv
from dataclasses import dataclass


def main():
    argp = argparse.ArgumentParser()
    argp.add_argument("a_index")
    argp.add_argument("b_index")
    argp.add_argument("c_index")
    args = argp.parse_args()

    a_index_path = args.a_index
    b_index_path = args.b_index
    c_index_path = args.c_index

    @dataclass
    class Record:
        filename: str
        sha256: str
        md5: str

        def __hash__(self):
            return int(self.sha256, 16)

    a_data = set()
    with open(a_index_path, 'r') as f:
        a_reader = csv.DictReader(f)
        for row in a_reader:
            a_data.add(Record(row['filename'], row['sha256'], row['md5']))

    b_data = set()
    with open(b_index_path, 'r') as f:
        b_reader = csv.DictReader(f)
        for row in b_reader:
            b_data.add(Record(row['filename'], row['sha256'], row['md5']))

    c_data = a_data.difference(b_data)
    with open(c_index_path, 'w+') as f:
        c_writer = csv.DictWriter(f, fieldnames=["filename", "sha256", "md5"])
        c_writer.writeheader()
        for r in c_data:
            c_writer.writerow({'filename': r.filename, 'sha256': r.sha256, 'md5': r.md5})


if __name__ == "__main__":
    main()
