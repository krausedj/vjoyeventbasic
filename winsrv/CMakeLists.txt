cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
add_subdirectory(winsockwrapper)

include_directories(vjoy/inc)
include_directories(../shared)
include_directories(../websocketpp)

project(eventforward)

find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)

add_library( vjoyinterface SHARED IMPORTED GLOBAL )
set_property(TARGET vjoyinterface PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.dll")
set_property(TARGET vjoyinterface PROPERTY IMPORTED_IMPLIB "${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.lib")
configure_file("${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.dll" "${CMAKE_CURRENT_BINARY_DIR}" COPYONLY)

add_executable(app main.cpp ../shared/crc_32.c)
target_compile_features(app PRIVATE cxx_std_17)
target_link_libraries(app vjoyinterface winsockwrapper)

add_executable(websock print_client.cpp)
target_compile_features(websock PRIVATE cxx_std_17)
target_link_libraries(websock ws2_32 OpenSSL::Crypto)