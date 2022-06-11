"""manipulator for my malware env."""

import functools
import multiprocessing
from signal import signal
from typing import List
import lief
from gym_malware.envs.controls import manipulate2
import signal

from fetch import fetch
import filebrowser


class MyManipulator(manipulate2.MalwareManipulator):
    """my own manipulator."""

    pass


ACTION_TABLE = {
    # 'do_nothing': identity,
    'overlay_append': 'overlay_append',
    'imports_append': 'imports_append',
    'section_rename': 'section_rename',
    'section_add': 'section_add',
    'section_append': 'section_append',
    'create_new_entry': 'create_new_entry',
    'remove_signature': 'remove_signature',
    'remove_debug': 'remove_debug',
    'upx_pack': 'upx_pack',
    'upx_unpack': 'upx_unpack',
    'break_optional_header_checksum': 'break_optional_header_checksum',
    #   'modify_exports' : modify_exports,
}


def modify_without_breaking(bytez: bytes, actions: List[str], seed=None) -> bytes:
    """Give a sequence of actions, run modifications in helper process.

    run modification in helper process to catch errors
    """
    for i, action in enumerate(actions):
        _action = ACTION_TABLE[action]

        def helper(_action, shared_list):
            def sig_handler(signum, frame):
                raise RuntimeError
            signal.signal(signal.SIGSEGV, sig_handler)

            bytez = bytes(shared_list[:])
            if type(_action) is str:
                _action = MyManipulator(bytez).__getattribute__(action)
            else:
                _action = functools.partial(_action, bytez)

            try:
                shared_list[:] = _action(seed)
            except (RuntimeError, UnicodeDecodeError, TypeError, lief.not_found) as e:
                print("===== exception in child process ====")
                print(e)

        manager = multiprocessing.Manager()
        shared_list = manager.list()
        shared_list[:] = bytez
        p = multiprocessing.Process(target=helper, args=(_action, shared_list))
        p.start()
        try:
            p.join(5)
        except multiprocessing.TimeoutError:
            print("==== timeouterror")
            p.terminate()
        # copy result from child process
        bytez = bytes(shared_list[:])

    import hashlib
    m = hashlib.sha256()
    m.update(bytez)
    print("new hash {}".format(m.hexdigest()))
    return bytez


if __name__ == "__main__":
    downloader = filebrowser.FileBrowserClient(
        hosts=[filebrowser.HostInfo("10.112.255.77", "8081", "admin", "daxiahyh")])
    fetcher = fetch.Fetcher(
        indexes=["../all.benign.csv", "../all.malware.csv"],
        downloader=downloader)
    bytez = fetcher.fetch(
        "47d8aed6a727a52b967f038e2c7234782e6f7ddbbaf2de1c2cbc8cb03fb995d4")
    with open("../output/origin.exe", 'wb') as f:
        f.write(bytez)
    print(hex(len(bytez)))
    manipulator = MyManipulator(bytez)
    bytez = manipulator.upx_pack()
    modify_without_breaking(bytez,
                            actions=['overlay_append', 'section_rename', 'section_add'])
    print("-------here-----")
    modify_without_breaking(bytez, actions=['imports_append'])
    binary = lief.PE.parse(bytez)
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write("../output/test.exe")
