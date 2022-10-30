
add_library(warnings INTERFACE)
target_compile_options(warnings INTERFACE
    -Werror=all
    -Werror=extra
    -Werror=pedantic
    # this generates too many errors, and im too lazy to do them all rn
    # -Werror=conversion
    -Weverything
    -Wno-c++98-compat
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


tcx_add_tests(builds)
