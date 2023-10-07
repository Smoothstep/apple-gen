if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND WIN32)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT")

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Xlinker /stack:0x10000,0x10000")
else ()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stack:0x10000,0x10000")
endif ()

message(${CMAKE_CXX_COMPILER_ID})

add_executable(test apple-gen.cpp)
target_include_directories(test PUBLIC ../include)
set_target_properties(test PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(test PROPERTIES COMPILE_FLAGS "-m64 /MTd")
#target_link_options(test PRIVATE -Xlinker /stack:1000000,1000000)

target_link_libraries(test PRIVATE apple_crypto)


#target_compile_options(test PRIVATE "-Xlinker /stack:0x100000,0x100000")
#install(TARGETS apple_crypto LIBRARY DESTINATION "/wrapper/rust/apple_crypto.a")
