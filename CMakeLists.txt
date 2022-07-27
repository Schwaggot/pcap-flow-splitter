cmake_minimum_required(VERSION 3.22)
project(pcap_flow_splitter)

set(CMAKE_CXX_STANDARD 17)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.74 REQUIRED COMPONENTS filesystem program_options)

add_subdirectory(libs/mmpr)

set(LIBTINS_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(libs/libtins)

add_executable(pcap_flow_splitter
        src/main.cpp
        src/Parser.cpp
        src/FlowManager.cpp
        src/emitter/StdOutEmitter.cpp
        )
target_include_directories(pcap_flow_splitter
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/sole
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/libtins/include
        )
target_link_libraries(pcap_flow_splitter
        PRIVATE
        pcap
        mmpr::mmpr
        tins
        Boost::filesystem
        Boost::program_options
        )
target_compile_options(pcap_flow_splitter
        PRIVATE
        -Wall
        -Wpedantic
        -Wextra
        $<$<CONFIG:Release>:-O3>
        )