#include <iostream>
#include <fstream>
#include <windows.h>

int main(){
    std::string file_path = "test_dll.dll";
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

    char* p = p_buff;

    //DOS头
    IMAGE_DOS_HEADER dos_header;
    memcpy(&dos_header, p, sizeof(IMAGE_DOS_HEADER));
    p += dos_header.e_lfanew;
    //NT头
    IMAGE_NT_HEADERS nt_headers;
    memcpy(&nt_headers, p, sizeof(IMAGE_NT_HEADERS));
    p += sizeof(IMAGE_NT_HEADERS);
    //PE头,文件头
    IMAGE_FILE_HEADER file_header = nt_headers.FileHeader;
    //可选头
    IMAGE_OPTIONAL_HEADER option_header = nt_headers.OptionalHeader;

    delete[] p_buff;
}