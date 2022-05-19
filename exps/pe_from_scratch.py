import os
from lief import PE
from keystone import * # keystone是汇编工具，capstone是反汇编工具，unicorn是模拟器

binary32 = PE.Binary("pe_from_scatch", PE.PE_TYPE.PE32)

# construct data
title = "LIFE is awesome\0"
title_addr = 0x2000 + binary32.imagebase
print(title_addr)
message = "Hello World\0"
message_addr = title_addr + len(title)

data = list(map(ord, title))
data += list(map(ord, message))

section_data = PE.Section(".data")
section_data.content = data
section_data.virtual_address = 0x2000

# construct code
user32 = binary32.add_library("user32.dll")
user32.add_entry("MessageBoxA")
kernel32 = binary32.add_library("kernel32.dll")
kernel32.add_entry("ExitProcess")

CODE = """
push 0x00             
push %s
push %s    
push 0                
call 0x304C
push 0               
call 0x3054
""" % (title_addr, message_addr)


try:
    ks = Ks(KS_ARCH_X86, KS_MODE_32) # 指令集和模式
    encoding, count = ks.asm(CODE)
except KsError as e:
    print("ERROR: %s" % e)

print(list(map(hex, encoding)))

section_text = PE.Section(".text")
section_text.content = encoding
section_text.virtual_address = 0x1000

section_text = binary32.add_section(section_text, PE.SECTION_TYPES.TEXT)
section_data = binary32.add_section(section_data, PE.SECTION_TYPES.DATA)
print(section_text)
print(section_data)

# relocation
# 在不确定.text段大小的时候，是没法确定IAT的位置的，必须先执行add_section(".text")，再执行predict_function_rva
print("ExitProcess", hex(binary32.predict_function_rva("kernel32.dll", "ExitProcess")))
print("MessageBoxA", hex(binary32.predict_function_rva("user32.dll", "MessageBoxA")))

# OEP
binary32.optional_header.addressof_entrypoint = section_text.virtual_address

# build
builder = PE.Builder(binary32)
builder.build_imports(True)
builder.build()
builder.write(os.path.join(os.path.dirname(__file__), "output", "pe_from_scratch.exe"))


