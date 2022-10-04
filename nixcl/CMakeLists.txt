cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project(nixcl)

add_executable(nixcl main.c)
target_compile_features(nixcl PRIVATE cxx_std_17)