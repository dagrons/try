import argparse
import csv
from dataclasses import dataclass


@dataclass
class Record:
    filename: str
    sha256: str
    md5: str

    def __hash__(self):
        return self.sha256


def main():
    argp = argparse.ArgumentParser()
    argp.add_argument("source_file")
    argp.add_argument("target_file")
    args = argp.parse_args()

    src_set = set()
    with open(args.source_file) as f:
        csv_reader = csv.DictReader(f, fieldnames=["filename", "sha256", "md5"])
        for row in csv_reader:
            src_set.add(Record(row['filename'], row['sha256'], row['md5']))

    with open(args.target_file) as f:
        csv_writer = csv.DictWriter(f, fieldnames=["filename", "sha256", "md5"])
        csv_writer.writeheader()
        for record in src_set:
            csv_writer.writerow([record.filename, record.sha256, record.md5])


if __name__ == "__main__":
    main()
