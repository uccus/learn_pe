#include <string>
#include <fstream>
#include <iostream>
#include "pe_analysis.h"

PEAnalysis::PEAnalysis(char* pe, int size)
    : data(pe)
    , _size(size)
{
}

PEAnalysis::~PEAnalysis()
{
    if (_size > 0){
        delete[] data;
    }
}

bool PEAnalysis::isPE()
{
    return (data && *((WORD*)data) == 0x5a4d);
}

IMAGE_DOS_HEADER* PEAnalysis::getDosHeader()
{
    if(!isPE()) return nullptr;
    return (IMAGE_DOS_HEADER*)data;
}

IMAGE_NT_HEADERS* PEAnalysis::getNTHeader()
{
    if(!isPE()) return nullptr;
    IMAGE_DOS_HEADER* dos = getDosHeader();
    char* p = data;
    p += dos->e_lfanew;

    return (IMAGE_NT_HEADERS*)p;
}

IMAGE_FILE_HEADER* PEAnalysis::getFileHeader()
{
    if(!isPE()) return nullptr;
    IMAGE_NT_HEADERS* nt_header = getNTHeader();
    return &nt_header->FileHeader;
}

IMAGE_OPTIONAL_HEADER* PEAnalysis::getOptionHeader()
{
    if(!isPE()) return nullptr;
    IMAGE_NT_HEADERS* nt_header = getNTHeader();
    return &nt_header->OptionalHeader;
}

std::vector<IMAGE_SECTION_HEADER*> PEAnalysis::getSections()
{
    std::vector<IMAGE_SECTION_HEADER*> out;
    if(!isPE()) return out;

    IMAGE_OPTIONAL_HEADER* op_header = getOptionHeader();
    IMAGE_SECTION_HEADER* section_begin = (IMAGE_SECTION_HEADER*)((char*)op_header + sizeof(IMAGE_OPTIONAL_HEADER));
    IMAGE_SECTION_HEADER tmp = { 0 };
    while(memcmp(section_begin, &tmp, sizeof(tmp)) != 0){
        out.push_back(section_begin);
        section_begin++;
    }

    return out;
}

int PEAnalysis::save(const std::string& file_path)
{
    std::ofstream ofs(file_path, std::ios::trunc | std::ios::binary);
    if (!ofs.is_open()){
        std::cout << "文件打开失败" << std::endl;
        return -1;
    }

    if (_size > 0)
        ofs.write(data, _size);
    ofs.close();
    return 0;
}

int PEAnalysis::rva2foa(int rva)
{
    std::vector<IMAGE_SECTION_HEADER*> sections = getSections();
    IMAGE_SECTION_HEADER* prev_section = nullptr;
    for (int i = 0; i < sections.size(); i++)
    {
        IMAGE_SECTION_HEADER* s = sections[i];
        if(s->VirtualAddress > (DWORD)rva){
            if (prev_section == nullptr){
                // rva在头里,直接返回
                return rva;
            }
            else{
                // 在前一节内
                if (prev_section->Misc.VirtualSize > prev_section->SizeOfRawData){
                    // 内存空间比在文件中大，此时的rva无法准确的转换到foa，通常这种情况下表示有许多未初始化的内容
                    return -1;
                }
                else{
                    return rva - prev_section->VirtualAddress + prev_section->PointerToRawData;
                }
            }
        }
        else{
            // 记录当前节，继续查找
            prev_section = s;
        }
    }

    return -1;
}

int PEAnalysis::addNewSection1(char** out_buf)
{
    //以第一个节为例
    IMAGE_SECTION_HEADER* first_section = getSections().front();
    IMAGE_SECTION_HEADER* last_section  = getSections().back();
    // 检查空间是否足够
    IMAGE_FILE_HEADER* file_header = getFileHeader();
    IMAGE_OPTIONAL_HEADER* op_header = getOptionHeader();
    int section_size = sizeof(IMAGE_SECTION_HEADER);
    if(op_header->SizeOfHeaders - ((char*)last_section + section_size - data) < 2 * section_size){
        std::cout << "节表末尾空间不足" << std::endl;
        return -1;
    }

    IMAGE_SECTION_HEADER tmp = { 0 };
    memcpy(&tmp, first_section, section_size);
    char* p_txt = ".text2";
    strncpy((char*)tmp.Name, p_txt, 7);
    int n_last = last_section->VirtualAddress + max(last_section->Misc.VirtualSize, last_section->SizeOfRawData);
    int n_last_raw = last_section->PointerToRawData + last_section->SizeOfRawData;
    tmp.VirtualAddress = n_last % op_header->SectionAlignment == 0 ? n_last : op_header->SectionAlignment * (n_last / op_header->SectionAlignment + 1);
    tmp.PointerToRawData = n_last_raw % op_header->FileAlignment == 0 ? n_last_raw : op_header->FileAlignment * (n_last_raw / op_header->FileAlignment + 1);
    
    char* buf = new char[op_header->SizeOfImage + first_section->SizeOfRawData];
    memcpy(buf, data, op_header->SizeOfImage);
    memcpy(buf + ((char*)last_section - data), &tmp, section_size);
    memcpy(buf + op_header->SizeOfImage, data + rva2foa(first_section->VirtualAddress), first_section->SizeOfRawData);
    *out_buf = buf;

    return op_header->SizeOfImage + first_section->SizeOfRawData;
}

int PEAnalysis::addNewSection2(char** out_buf)
{

    return 0;
}

int PEAnalysis::addNewSection3(char** out_buf)
{

    return 0;
}
