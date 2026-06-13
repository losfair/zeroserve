cmake_minimum_required(VERSION 2.8)
project( win-c )
set(SOURCES source/getopt.c)
include_directories( include )
add_library(libwinc ${SOURCES})
add_executable(testLibwinc test/test.cpp)
target_link_libraries(testLibwinc libwinc)

add_executable(test_getopt_long test/test_getopt_long.cpp)
target_link_libraries(test_getopt_long libwinc)

install(TARGETS libwinc DESTINATION lib)
