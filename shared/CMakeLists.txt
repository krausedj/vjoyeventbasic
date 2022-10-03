cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project(test)

add_executable(test crc_32.c test.cpp)
target_compile_features(test PRIVATE cxx_std_17)