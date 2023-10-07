cmake_minimum_required(VERSION 3.20)
enable_language(ASM)
set(CMAKE_SYSTEM_PROCESSOR "x86_64")
set(CMAKE_CXX_STANDARD 20)

project(apple_gen LANGUAGES C CXX ASM)

string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} arch)

set(ASM_SOURCES
src/asm/${arch}/imd.s 
src/asm/${arch}/encrypt.s
)

set(LIBRARY_SOURCES
    src/crypt.cpp
)

if (BUILD_SHARED_LIB)
    set(LIB_TYPE SHARED)
else ()
    set(LIB_TYPE STATIC)
endif ()

if (CMAKE_GENERATOR MATCHES "Visual Studio")
    add_library(apple_crypto_asm ${LIB_TYPE} ${ASM_SOURCES})

    message("Using Visual Studio (requires Clang / ClangCL)")
    
    # Need to compile asm files due to VS not using clang compiler for it automatically
    set(CMAKE_ASM_COMPILER "clang-cl")

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /NODEFAULTLIB:libcmt")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT ")

    #set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")

    add_custom_command(
        OUTPUT "imd.obj"
        COMMAND ${CMAKE_CXX_COMPILER} /c ${CMAKE_SOURCE_DIR}/src/asm/${arch}/imd.s ${CMAKE_SOURCE_DIR}/src/asm/${arch}/encrypt.s
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Compiling .s files with Clang"
    )

    add_custom_command(
        OUTPUT "encrypt.obj"
        COMMAND ${CMAKE_CXX_COMPILER} /c ${CMAKE_SOURCE_DIR}/src/asm/${arch}/imd.s ${CMAKE_SOURCE_DIR}/src/asm/${arch}/encrypt.s
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Compiling .s files with Clang"
    )

    #set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    #target_link_libraries(apple_crypto ${CMAKE_CURRENT_BINARY_DIR}/imd.obj ${CMAKE_CURRENT_BINARY_DIR}/encrypt.obj)
    add_library(apple_crypto ${LIB_TYPE} ${LIBRARY_SOURCES})
    target_sources(apple_crypto PRIVATE imd.obj)
    target_sources(apple_crypto PRIVATE encrypt.obj)

else ()
    add_library(apple_crypto ${LIB_TYPE} ${LIBRARY_SOURCES} ${ASM_SOURCES})
endif()


if (BUILD_SHARED_LIB)
    target_compile_definitions(apple_crypto PRIVATE _BUILD_SHARED)
endif ()

target_include_directories(apple_crypto PUBLIC include)
set_target_properties(apple_crypto PROPERTIES LINKER_LANGUAGE CXX)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_FRONTEND_VARIANT MATCHES "MSVC")
    set_target_properties(apple_crypto PROPERTIES COMPILE_FLAGS "/clang:-masm=intel /MT")
else ()
    set_target_properties(apple_crypto PROPERTIES COMPILE_FLAGS "-masm=intel -static -lstdc++ -static-libgcc -static-libstdc++")
endif ()

set_target_properties(apple_crypto PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

if (BUILD_TEST)
    add_subdirectory(test)
endif ()

install(TARGETS apple_crypto DESTINATION ${CMAKE_INSTALL_PREFIX})
