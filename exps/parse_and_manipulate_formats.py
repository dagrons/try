import os
import lief

from filebrowser import FileBrowserClient

save_folder = os.path.join(os.path.dirname(__file__), "../download")

fbrowser_client = FileBrowserClient(host="10.112.254.160", port="8082")
fbrowser_client.authenticate("admin", "daxiahyh")

fbrowser_client.download_auth_file("DikeDataset-main/files/malware/00a0d8c3adc67e930fd89331e4e41cfe2a7128072d5d3ca0ec369da5b7847a45.exe",
                                   os.path.join(save_folder, "a"))
binary = lief.parse("download/a")

for section in binary.sections:
    print(section.name)
    print("===================================")
    print("section size: ", hex(section.size))
    print("section content size:", hex(len(section.content)))
    print("section margin size: ", hex(section.size - len(section.content)))
    print("===================================")

print(binary.header)
print(binary.optional_header)

print("============Imported Functions================")
for func in binary.imported_functions:
    print(func)

print("============Imported Library==================")
for imported_library in binary.imports:
    print("----Library name: " + imported_library.name, "-----")
    for func in imported_library.entries:
        if not func.is_ordinal:
            print(func.name, func.iat_address)

builder = lief.PE.Builder(binary)
builder.build_imports(True) # rebuild imports table into another section
builder.patch_imports(True) # patch the original import table to redirect functions to new import tables，
# 这里相当于在header中已经修改了对应的Import Directory和Import Address Directory的偏移地址，让它们指向了.l1中的对应项

builder.build()
builder.write("download/result.exe")



