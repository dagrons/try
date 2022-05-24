import abc
import os.path
from abc import ABC, abstractmethod

import numpy as np
import filebrowser
import lief
from capstone import *


class Feature(ABC):
    """interface for all feature type"""

    def __init__(self):
        super().__init__()
        self.dtype = np.float32
        self.name = ''

    @abstractmethod
    def __call__(self):
        """call for feature extraction"""

    def __repr__(self):
        return '{}({})'.format(self.name, self.dim)


class BaseFeature(Feature, ABC):
    """interface & base impl for all base feature type"""

    def __init__(self, dim):
        super(BaseFeature, self).__init__()
        self.dim = dim

    def empty(self):
        return np.zeros((self.dim,), dtype=np.float32)


class RawBytesFeature(Feature):
    """raw bytes from whole exe"""

    def __init__(self):
        super(RawBytesFeature, self).__init__()
        self.bytez = None

    def __call__(self, binary):
        builder = lief.PE.Builder(binary)
        builder.build()
        self.bytez = bytearray(builder.get_build())
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
    """opcode sequence from binary"""

    def __init__(self, only_text=False):
        super(OpCodeFeature, self).__init__()
        self.only_text = only_text

    def __call__(self, binary):
        opcode_seq = []
        disasm_sections = []
        for sec in binary.sections:
            if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in sec.characteristics_lists:
                disasm_sections.append(sec.name)
        if self.only_text:
            disasm_sections = [".text"]
        for name in disasm_sections:
            section = binary.get_section(name)
            try: # some sections may contains no content
                bytes = section.content.tobytes()
            except:
                continue
            if binary.header.machine == lief.PE.MACHINE_TYPES.I386:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            else:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(bytes, section.virtual_address):
                opcode_seq.append(i.mnemonic)
        return opcode_seq


if __name__ == "__main__":
    fclient = filebrowser.FileBrowserClient().with_host(host="10.112.108.112", port="8081", username="admin", password="daxiahyh")
    download_list = [
        "dagongren/DikeDataset-main/files/benign/0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906.exe",
    ]
    opcode_set = set()
    for file in download_list:
        save_path = os.path.join("../download", file.split("/")[-1])
        print(save_path)
        fclient.download_auth_file(
            file,
            save_path)
        binary = lief.PE.parse(save_path)
        bytes = RawBytesFeature()
        print(hex(len(bytes(binary))))
        print(bytes.image())
        opcodes = OpCodeFeature()
        opcode_set.update(opcodes(binary))
    print(len(opcode_set))

