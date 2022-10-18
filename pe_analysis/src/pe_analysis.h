#ifndef __SRC_PE_ANALYSIS_H__
#define __SRC_PE_ANALYSIS_H__

#include <vector>
#include <windows.h>

class PEAnalysis{
public:
    PEAnalysis(char* pe, int size);
    ~PEAnalysis();

    // 是否是pe文件
    bool isPE();
    // 获取DOS头
    IMAGE_DOS_HEADER* getDosHeader();
    // 获取NT头
    IMAGE_NT_HEADERS* getNTHeader();
    // 获取文件头
    IMAGE_FILE_HEADER* getFileHeader();
    // 获取可选头
    IMAGE_OPTIONAL_HEADER* getOptionHeader();
    // 获取节表
    std::vector<IMAGE_SECTION_HEADER*> getSections();
    // 输出到文件
    int save(const std::string& file_path);
    // RVA TO FOA
    int rva2foa(int rva);
    // 新增节
    // 方式一: 在普通节后新增，要求有两个IMAGE_SECTION_HEADER的大小空出
    int addNewSection1(char** out_buf);
    // 方式二：删除dos存根数据，提升NT头和所有节表，要求dos存根的数据有两个IMAGE_SECTION_HEADER的位置
    int addNewSection2(char** out_buf);
    // 方式三：扩大最后一个节的内容
    int addNewSection3(char** out_buf);

private:
    char* data;
    int   _size;
};

#endif  // __SRC_PE_ANALYSIS_H__
