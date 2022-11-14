
add_library(warnings INTERFACE)
target_compile_options(warnings INTERFACE
    -Werror=all
    -Werror=extra
    -Werror=pedantic
    # this generates too many errors, and im too lazy to do them all rn
    # -Werror=conversion
    $<$<CXX_COMPILER_ID:Clang>:-Weverything -Wno-c++98-compat>
)

function(tcx_add_test NAME)
    add_executable(${NAME}_test)
    target_link_libraries(${NAME}_test PRIVATE warnings uring++)
    target_sources(${NAME}_test PRIVATE ${CMAKE_SOURCE_DIR}/tests/${NAME}.cpp)
    add_test(NAME ${NAME} COMMAND ${NAME}_test)
    endfunction()

function(tcx_add_tests)
    foreach(NAME IN LISTS ARGV)
        tcx_add_test(${NAME})
    endforeach()
endfunction()

function(enable_cpp20)
    foreach(NAME IN LISTS ARGV)
        set_target_properties(${NAME}_test PROPERTIES CXX_STANDARD 17 CMAKE_CXX_STANDARD_REQUIRED ON)
    endforeach()
endfunction()


tcx_add_tests(builds17 builds20 instantiation17 instantiation20)
enable_cpp20(builds20 instantiation20)
