cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project(wsr)

#socket.h conflicts, so highly isolate this into shared library to further limit pollution of system headers and library interfaces
add_library(winsockwrapper SHARED
    winsockwrapper.cpp
)
target_link_libraries(winsockwrapper ws2_32)
