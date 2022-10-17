cmake_minimum_required(VERSION 3.12)
project(peAnalysis)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/../output)

add_compile_options(/utf-8)
add_executable(peAnalysis src/main.cpp)
# target_link_libraries(peAnalysis test_dll)