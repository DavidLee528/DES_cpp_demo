cmake_minimum_required(VERSION 3.0)

project(DES)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(des src/des.cpp src/test_des.cpp)

add_compile_options(-Wall -O3 -v)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR})