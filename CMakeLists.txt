cmake_minimum_required(VERSION 2.4)

include_directories(vjoy/inc)

project(eventforward)

add_library( vjoyinterface SHARED IMPORTED GLOBAL )
set_property(TARGET vjoyinterface PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.dll")
set_property(TARGET vjoyinterface PROPERTY IMPORTED_IMPLIB "${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.lib")
configure_file("${PROJECT_SOURCE_DIR}/vjoy/lib/amd64/vJoyInterface.dll" "${CMAKE_CURRENT_BINARY_DIR}" COPYONLY)

add_executable(app main.cpp)
target_link_libraries(app vjoyinterface)