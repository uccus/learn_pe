cmake_minimum_required(VERSION 3.12)
project(windows_test)

set(DLL_SRC src/test_dll.cpp src/test_dll.def)

add_library(test_dll SHARED ${DLL_SRC})

add_executable(test_exe src/test_exe.cpp)
target_link_libraries(test_exe test_dll)