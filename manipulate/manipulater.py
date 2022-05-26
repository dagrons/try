import lief
from gym_malware.envs.controls import manipulate2

from fetch import fetch
import filebrowser

class MyManipulator(manipulate2.MalwareManipulator):
    pass

if __name__ == "__main__":     
    downloader = filebrowser.FileBrowserClient(hosts=[filebrowser.HostInfo("10.112.255.77", "8081", "admin", "daxiahyh")])
    fetcher = fetch.Fetcher(indexes=["../all.benign.csv", "../all.malware.csv"], downloader = downloader)
    bytez = fetcher.fetch("47d8aed6a727a52b967f038e2c7234782e6f7ddbbaf2de1c2cbc8cb03fb995d4")
    print(hex(len(bytez)))
    import ipdb; ipdb.set_trace()    
    manipulator = MyManipulator(bytez)    
    bytez = manipulator.imports_append()
    binary = lief.PE.parse(bytez)
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write("../output/test.exe")

