// #include <iostream>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
//#include "test_dll.h"
#define MAX_PATH_SIZE 260

int test_add(int, int);

std::string getCurrentPath()
{
    char current_absolute_path[MAX_PATH_SIZE + 1] = {0};
    //获取当前程序绝对路径
    int cnt = readlink("/proc/self/exe", current_absolute_path, MAX_PATH_SIZE);
    if (cnt < 0 || cnt >= MAX_PATH_SIZE) {
        return "./";
    }

    //获取当前目录绝对路径，即去掉程序名
    int i;
    for (i = cnt; i >= 0; --i) {
        if (current_absolute_path[i] == '/') {
            current_absolute_path[i + 1] = '\0';
            return current_absolute_path;
        }
    }
    return "./";
}

int main()
{
    std::string path = getCurrentPath();
    // std::cout << test_add(1, 10) << std::endl;
    int ret = test_add(1, 10);
    printf("%d", ret);
    return 0;
}