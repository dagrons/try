"""c.csv = a.csv - b.csv"""

import argparse
import csv
from dataclasses import dataclass


@dataclass
class Record:
    filename: str
    sha256: str
    md5: str

    def __hash__(self):
        return int(self.sha256, 16)


def main():
    argp = argparse.ArgumentParser()
    argp.add_argument("infiles", nargs='+', required=True)
    argp.add_argument("ofile")
    args = argp.parse_args()

    in_data = set()
    for infile in args.infiles:
        with open(infile, 'r') as f:
            in_reader = csv.DictReader(f, fieldnames=['filename', 'sha256', 'md5'])
            for row in in_reader:
                in_data.add(Record(row['filename'], row['sha256'], row['md5']))

    with open(args.ofile, 'w+') as f:
        o_writer = csv.DictWriter(f, fieldnames=["filename", "sha256", "md5"])
        o_writer.writeheader()
        for r in in_data:
            o_writer.writerow({'filename': r.filename, 'sha256': r.sha256, 'md5': r.md5})


if __name__ == "__main__":
    main()
