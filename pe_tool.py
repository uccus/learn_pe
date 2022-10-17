import sys
import pefile
from pefile import SectionStructure

pe = pefile.PE("windows/tmp/test_dll.dll")
# print(pe.DOS_HEADER)
# print(pe.NT_HEADERS)
# print(pe.get_string_at_rva(pe.DOS_HEADER.e_lfanew))
# print(hex(pe.generate_checksum()))
# pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
print(pe.FILE_HEADER.NumberOfSections)
print(hex(pe.FILE_HEADER.SizeOfOptionalHeader))

section = pe.sections[0]
lastSection = pe.sections[pe.FILE_HEADER.NumberOfSections - 1]

# 新增节
# 1. 节数量+1
pe.FILE_HEADER.NumberOfSections += 1
# 2. 准备新的节的信息,其中需要确定VirtualAddress,PointerToRawData
newSection = SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
newSection.Name = ".text2"
newSection.Misc = section.Misc
newSection.Misc_VirtualSize = section.Misc_VirtualSize
newSection.VirtualAddress = section.VirtualAddress
newSection.SizeOfRawData = section.SizeOfRawData
newSection.PointerToRawData = section.PointerToRawData
newSection.PointerToRelocations = section.PointerToRelocations
newSection.PointerToLinenumbers = section.PointerToLinenumbers
newSection.NumberOfRelocations = section.NumberOfRelocations
newSection.NumberOfLinenumbers = section.NumberOfLinenumbers
newSection.Characteristics = section.Characteristics
