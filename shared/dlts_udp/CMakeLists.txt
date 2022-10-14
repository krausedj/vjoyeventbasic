cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project(ssl_dlts_udp)
find_package(OpenSSL REQUIRED)

add_executable(dlts_udp dtls_udp.c)
target_compile_features(dlts_udp PRIVATE cxx_std_17)
target_link_libraries(dlts_udp OpenSSL::SSL)