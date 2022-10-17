// #include <iostream>
#include <stdio.h>
//#include "test_dll.h"

int test_add(int, int);

int main()
{
    // std::cout << test_add(1, 10) << std::endl;
    int ret = test_add(1, 10);
    printf("%d", ret);
    return 0;
}