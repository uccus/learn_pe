#include <iostream>
#include <fstream>
#include <windows.h>
#include "pe_analysis.h"

int main(){
    std::string file_path = "test_exe.exe";
    std::ifstream ifs(file_path, std::ios::ate|std::ios::binary);
    if (!ifs.is_open()){
        std::cout << "文件不存在" << std::endl;
        return 0;
    }

    int f_size = (int)ifs.tellg();
    ifs.seekg(std::ios::beg);

    char* p_buff = new char[f_size];
    if (p_buff == NULL){
        std::cout << "内存申请失败" << std::endl;
        ifs.close();
        return 0;
    }
    ifs.read(p_buff, f_size);
    ifs.close();

    PEAnalysis pe(p_buff, f_size);

    IMAGE_DOS_HEADER* dos_header = pe.getDosHeader();
    IMAGE_NT_HEADERS* nt_header = pe.getNTHeader();
    IMAGE_FILE_HEADER* file_header = pe.getFileHeader();
    std::vector<IMAGE_SECTION_HEADER*> sections = pe.getSections();
    int foa = pe.rva2foa(0xC000);

    char* newS_1 = nullptr;
    int n_size = pe.addNewSection2(&newS_1);
    PEAnalysis pe_1(newS_1, n_size);
    pe_1.save("./5.exe");

    delete[] p_buff;
}