import filebrowser
import lief
from gym_malware.envs.controls import manipulate2

from fetch import fetch


class MyManipulator(manipulate2.MalwareManipulator):
    pass


if __name__ == "__main__":
    downloader = filebrowser.FileBrowserClient(hosts=[filebrowser.HostInfo("10.112.255.77", "8081", "admin", "daxiahyh")])
    fetcher = fetch.Fetcher(indexes=["../all.benign.csv", "../all.malware.csv"], downloader = downloader)
    bytez = fetcher.fetch("fa92ee9f25abbcc1b32d7567f8d68c34ce676fc853bca35a310d329107024535")
    print(hex(len(bytez)))
    manipulator = MyManipulator(bytez)
    print(hex(len(manipulator.overlay_append())))
    bytez = manipulator.imports_append()
    binary = lief.PE.parse(bytez)
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write("../output/test.exe")



