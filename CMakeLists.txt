cmake_minimum_required(VERSION 3.18)
project(eKoolCpp VERSION 0.1)

set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(ext/json)

include_directories(ext/json/include ext/httplib)

add_library(eKoolCpp eKoolCpp.cpp)
target_link_libraries(eKoolCpp ssl crypto)