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
    argp.add_argument("source_file")
    argp.add_argument("target_file")
    args = argp.parse_args()

    src_set = set()
    with open(args.source_file, 'r') as f:
        csv_reader = csv.DictReader(f, fieldnames=["filename", "sha256", "md5"])
        for row in csv_reader:
            src_set.add(Record(row['filename'], row['sha256'], row['md5']))

    with open(args.target_file, 'w+') as f:
        csv_writer = csv.DictWriter(f, fieldnames=["filename", "sha256", "md5"])
        csv_writer.writeheader()
        for record in src_set:
            csv_writer.writerow({"filename": record.filename, "sha256": record.sha256, "md5": record.md5})


if __name__ == "__main__":
    main()
