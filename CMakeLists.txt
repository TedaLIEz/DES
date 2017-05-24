cmake_minimum_required(VERSION 3.6)
project(des)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES src/main.cpp src/dae.cpp src/keygen.cpp src/aes.cpp)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -Wall")
include_directories(include)

set(C_PARSER_HEAD include/)
add_executable(des ${SOURCE_FILES} ${C_PARSER_HEAD})
