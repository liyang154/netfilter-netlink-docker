cmake_minimum_required(VERSION 3.15)
project(client C)

set(CMAKE_C_STANDARD 99)

add_executable(client main.c)
target_link_libraries(client pthread)