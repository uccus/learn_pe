cmake_minimum_required(VERSION 3.12)
project(peAnalysis)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../output)

add_compile_options(/utf-8)

aux_source_directory(./src SRC)
add_executable(peAnalysis ${SRC})
# target_link_libraries(peAnalysis test_dll)
