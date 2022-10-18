cmake_minimum_required(VERSION 3.0)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project(ssl_dtls_udp)
find_package(OpenSSL REQUIRED)

add_library(dtls_udp SHARED
    sock_dtls_udp.c
)

target_link_libraries(dtls_udp OpenSSL::SSL)
if(WIN32)
  target_link_libraries(dtls_udp ws2_32)
endif()

add_executable(test_server test_server.c)
target_compile_features(test_server PRIVATE cxx_std_17)
target_link_libraries(test_server OpenSSL::SSL dtls_udp)

add_executable(test_client test_client.c)
target_compile_features(test_client PRIVATE cxx_std_17)
target_link_libraries(test_client OpenSSL::SSL dtls_udp)

add_executable(dtls_ref dtls_udp.c)
target_link_libraries(dtls_ref OpenSSL::SSL)
if(WIN32)
  target_link_libraries(dtls_ref ws2_32)
endif()
