cmake_minimum_required(VERSION 3.27)
project(covert_canal)

set(CMAKE_CXX_STANDARD 17)

add_executable(covert_canal main.cpp
        covert.h)
find_library(PCAP_LIBRARY pcap)
include_directories("C://WpdPack//Include")
target_link_libraries(covert_canal PRIVATE ${PCAP_LIBRARY})
target_link_libraries(covert_canal PRIVATE IPHLPAPI.lib)
target_link_libraries(covert_canal PRIVATE ws2_32.lib)

