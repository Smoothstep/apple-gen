if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Xlinker /stack:0x10000,0x10000")
else ()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stack:0x10000,0x10000")
endif ()

message(${CMAKE_CXX_COMPILER_ID})
unset(CMAKE_IMPORT_LIBRARY_SUFFIX)

add_executable(test_crypto apple-gen.cpp)
target_include_directories(test_crypto PUBLIC ../include)
set_target_properties(test_crypto PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(test_crypto PROPERTIES COMPILE_FLAGS "-m64")
target_link_libraries(test_crypto PRIVATE apple_crypto)