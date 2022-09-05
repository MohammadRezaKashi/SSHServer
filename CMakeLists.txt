cmake_minimum_required(VERSION 3.0.0)
project(bbServer VERSION 0.1.0)

include(CTest)
enable_testing()
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/extern") # add googletest subdirectory
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/extern/googletest/googletest/include") # this is so we can #include <gtest/gtest.h>
add_executable(mytests "${CMAKE_CURRENT_SOURCE_DIR}/tests/mytests.cpp") # add this executable

target_link_libraries(mytests PRIVATE ssh gtest) # link google test to this executable

find_package (libssh REQUIRED)

add_test(NAME MyTests COMMAND mytests)

file(GLOB SOURCES "source/*.cpp")

add_executable(bbServer main.cpp ${SOURCES})

target_include_directories(bbServer PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/headers")
target_link_libraries(bbServer ssh)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
