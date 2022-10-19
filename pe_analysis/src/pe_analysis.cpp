#include <string>
#include <fstream>
#include <iostream>
#include "pe_analysis.h"

PEAnalysis::PEAnalysis(char* pe, int size)
    : data(nullptr)
    , _size(size)
{
    if (_size > 0) {
        data = new char[_size];
        memcpy(data, pe, _size);
    }
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

    // 需要修改的内容：
    // 1. 文件头中节的NumberOfSections
    file_header->NumberOfSections += 1;
    // 2. 可选头中的SizeOfImage
    int old_image_size = op_header->SizeOfImage;
    int new_size = first_section->SizeOfRawData % op_header->FileAlignment == 0 ? 
        first_section->SizeOfRawData : 
        op_header->FileAlignment * (first_section->SizeOfRawData / op_header->FileAlignment + 1);
    op_header->SizeOfImage += new_size;
    // 3. 补充新节的描述信息
    IMAGE_SECTION_HEADER tmp = { 0 };
    memcpy(&tmp, first_section, section_size);
    char* p_txt = ".text2";
    strncpy((char*)tmp.Name, p_txt, 7);
    int n_last = last_section->VirtualAddress + max(last_section->Misc.VirtualSize, last_section->SizeOfRawData);
    int n_last_raw = last_section->PointerToRawData + last_section->SizeOfRawData;
    tmp.VirtualAddress = n_last % op_header->SectionAlignment == 0 ? n_last : op_header->SectionAlignment * (n_last / op_header->SectionAlignment + 1);
    tmp.PointerToRawData = n_last_raw % op_header->FileAlignment == 0 ? n_last_raw : op_header->FileAlignment * (n_last_raw / op_header->FileAlignment + 1);
    // 4. 新节的内容追加到末尾
    char* buf = new char[_size + new_size];
    memset(buf, 0, _size + new_size);
    // 拷贝原内容
    memcpy(buf, data, _size);
    // 追加节
    memcpy(buf + ((char*)last_section - data + section_size), &tmp, section_size);
    // 追加节对应内容
    memcpy(buf + tmp.PointerToRawData, data + first_section->PointerToRawData, first_section->SizeOfRawData);
    *out_buf = buf;

    return _size + new_size;
}

int PEAnalysis::addNewSection2(char** out_buf)
{
    // 以第一个节为例
    IMAGE_DOS_HEADER* dos_header = getDosHeader();
    IMAGE_FILE_HEADER* file_header = getFileHeader();
    IMAGE_OPTIONAL_HEADER* op_header = getOptionHeader();
    IMAGE_SECTION_HEADER* first_section = getSections().front();
    IMAGE_SECTION_HEADER* last_section = getSections().back();
    // 检查dos存根数据的大小 + 最后一个节后的空白是否可以放下两个节
    int n_dos_stub = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    int n_section_left_space = op_header->SizeOfHeaders - ((char*)last_section + sizeof(IMAGE_SECTION_HEADER) - data);
    if (n_dos_stub + n_section_left_space < 2 * sizeof(IMAGE_SECTION_HEADER)){
        std::cout << "dos存根空间+节后空间不足" << std::endl;
        return -1;
    }
    // 提升NT头+所有节表,干掉dos存根
    memcpy(data + sizeof(IMAGE_DOS_HEADER), data + dos_header->e_lfanew, op_header->SizeOfHeaders - dos_header->e_lfanew);
    // 修改dos头指向
    dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    // 刷新头指针
    file_header = getFileHeader();
    op_header = getOptionHeader();
    first_section = getSections().front();
    last_section = getSections().back();
    // 节表尾部清零
    memset((char*)last_section + sizeof(IMAGE_SECTION_HEADER), 0, op_header->SizeOfHeaders - ((char*)last_section + sizeof(IMAGE_SECTION_HEADER) - data));

    return addNewSection1(out_buf);
    //*out_buf = data;
    //return _size;
}

int PEAnalysis::addNewSection3(char** out_buf)
{
    IMAGE_DOS_HEADER* dos_header = getDosHeader();
    IMAGE_FILE_HEADER* file_header = getFileHeader();
    IMAGE_OPTIONAL_HEADER* op_header = getOptionHeader();
    IMAGE_SECTION_HEADER* first_section = getSections().front();
    IMAGE_SECTION_HEADER* last_section = getSections().back();

    // 以第一个节为例
    int n_raw_size = first_section->SizeOfRawData % op_header->FileAlignment == 0 ? first_section->SizeOfRawData :
        op_header->FileAlignment * (first_section->SizeOfRawData / op_header->FileAlignment + 1);

    last_section->SizeOfRawData += n_raw_size;
    last_section->Misc.VirtualSize += n_raw_size;
    last_section->Characteristics |= first_section->Characteristics;

    char* buf = new char[_size + n_raw_size];
    memcpy(buf, data, _size);
    memset(buf + _size, 0, n_raw_size);
    memcpy(buf + _size, data + first_section->PointerToRawData, first_section->SizeOfRawData);
    *out_buf = buf;

    return 0;
}
