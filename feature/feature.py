import os.path

import numpy as np
import filebrowser
import lief
from capstone import *


class Feature:
    """interface for all feature type"""

    def __init__(self):
        super().__init__()
        self.dtype = np.float32
        self.name = ''

    def __call__(self):
        return NotImplementedError

    def __repr__(self):
        return '{}({})'.format(self.name, self.dim)


class BaseFeature(Feature):
    """interface & base impl for all base feature type"""

    def __init__(self, dim):
        super(BaseFeature, self).__init__()
        self.dim = dim

    def empty(self):
        return np.zeros((self.dim,), dtype=np.float32)


class RawBytesFeature(Feature):
    """raw bytes from whole exe"""

    def __init__(self, exe_path):
        super(RawBytesFeature, self).__init__()
        with open(exe_path, 'rb') as f:
            self.bytez = f.read()

    def __call__(self):
        return self.bytez

    def image(self, width=256):
        total_size = len(self.bytez)
        rem = total_size % width
        height = total_size // width
        arr = np.frombuffer(self.bytez, dtype=np.uint8)
        if rem != 0:
            height += 1
            arr = np.pad(arr, (0, width-rem), 'constant')
        return arr.reshape((height, width))


class OpCodeFeature(Feature):
    """opcode sequence from all executable sections"""

    def __init__(self, exe_path, only_text=False):
        super(OpCodeFeature, self).__init__()
        self.binary = lief.PE.parse(exe_path)
        self.only_text = only_text

    def __call__(self):
        opcode_seq = []
        disasm_sections = []
        for sec in self.binary.sections:
            if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in sec.characteristics_lists:
                disasm_sections.append(sec.name)
        if self.only_text:
            disasm_sections = [".text"]
        for name in disasm_sections:
            section = self.binary.get_section(name)
            try: # some sections may contains no content
                bytes = section.content.tobytes()
            except:
                continue
            if self.binary.header.machine == lief.PE.MACHINE_TYPES.I386:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            else:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(bytes, section.virtual_address):
                opcode_seq.append(i.mnemonic)
        return opcode_seq


if __name__ == "__main__":
    fclient = filebrowser.FileBrowserClient(host="10.112.254.160", port="8082")
    fclient.authenticate("admin", "daxiahyh")
    download_list = [
        "malware/DikeDataset-main/files/benign/0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906.exe",
    ]
    opcode_set = set()
    for file in download_list:
        save_path = os.path.join("../download", file.split("/")[-1])
        print(save_path)
        fclient.download_auth_file(
            file,
            save_path)
        bytes = RawBytesFeature(save_path)
        print(hex(len(bytes())))
        print(bytes.image())
        opcodes = OpCodeFeature(save_path)
        opcode_set.update(opcodes())
    print(len(opcode_set))
