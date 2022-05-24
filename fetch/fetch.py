import csv
import tempfile

import filebrowser
from typing import List


class Fetcher:
    def __init__(self, indexes: List[str] = [], downloader: filebrowser.FileBrowserClient = None):
        self.sha256_to_fpath = {}
        self.md5_to_fpath = {}
        self.downloader = downloader
        self.cache = {}
        for fpath in indexes:
            with open(fpath, 'r') as f:
                csv_reader = csv.DictReader(f, fieldnames=['filename', 'sha256', 'md5'])
                for line in csv_reader:
                    if line['filename'] == 'filename':
                        continue
                    self.sha256_to_fpath[line['sha256']] = line['filename']
                    self.md5_to_fpath[line['md5']] = line['filename']

    def fetch(self, hash: str, save_path: str = None):
        if hash in self.cache:
            return open(self.cache[hash], 'rb')
        if save_path is None:
            _, save_path = tempfile.mkstemp()
        if len(hash) == 32:
            filename = self.md5_to_fpath[hash]
        elif len(hash) == 64:
            filename = self.sha256_to_fpath[hash]
        else:
            raise ValueError
        self.downloader.download_auth_file(filename, save_path)
        self.cache[hash] = save_path
        return open(save_path, 'rb').read()


if __name__ == '__main__':
    downloader = filebrowser.FileBrowserClient(
        hosts=[filebrowser.HostInfo("10.112.108.112", "8081", "admin", "daxiahyh")])
    fetcher = Fetcher(indexes=["../all.benign.csv", "../all.malware.csv"],
                      downloader=downloader)
    bytez = fetcher.fetch("0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906")
    print(hex(len(bytez)))
