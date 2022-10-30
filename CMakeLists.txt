cmake_minimum_required(VERSION 3.16)
project(uring++)

add_library(uring++ INTERFACE)
set_target_properties(uring++ PROPERTIES CXX_STANDARD 17 CMAKE_CXX_STANDARD_REQUIRED ON)
target_compile_features(uring++ INTERFACE cxx_std_17)
target_include_directories(uring++ INTERFACE
    ${CMAKE_SOURCE_DIR}/include/
)
target_sources(uring++ INTERFACE
    ${CMAKE_SOURCE_DIR}/include/uring++/uring++.hpp
)

if (ENABLE_TESTING)
    enable_testing()
    include(CTest)
    add_subdirectory(tests)
endif()
