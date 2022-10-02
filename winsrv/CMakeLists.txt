cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)


include_directories(vjoy/inc)

project(eventforward)

add_library( vjoyinterface SHARED IMPORTED GLOBAL )
set_property(TARGET vjoyinterface PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.dll")
set_property(TARGET vjoyinterface PROPERTY IMPORTED_IMPLIB "${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.lib")
configure_file("${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.dll" "${CMAKE_CURRENT_BINARY_DIR}" COPYONLY)

#socket.h conflicts, so highly isolate this into shared library to further limit pollution of system headers and library interfaces
add_library(winsockwrapper SHARED
    winsockwrapper.cpp
)
target_link_libraries(winsockwrapper ws2_32)

add_executable(app main.cpp)
target_compile_features(app PRIVATE cxx_std_17)
target_link_libraries(app vjoyinterface winsockwrapper)