cmake_minimum_required(VERSION 3.20)
project(MQ2RmlUi LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "MQ2RmlUi targets the 32-bit RoF2 emu client; configure with -A Win32")
endif()

find_package(RmlUi CONFIG REQUIRED)

# Import libraries generated from the shipped MacroQuest DLLs' export tables.
set(MQ_IMPORT_DIR ${CMAKE_CURRENT_BINARY_DIR}/importlibs)
file(MAKE_DIRECTORY ${MQ_IMPORT_DIR})
foreach(lib MQ2Main imgui)
    add_custom_command(
        OUTPUT ${MQ_IMPORT_DIR}/${lib}.lib
        COMMAND ${CMAKE_AR} /nologo /machine:x86 /def:${CMAKE_CURRENT_SOURCE_DIR}/defs/${lib}.def /out:${MQ_IMPORT_DIR}/${lib}.lib
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/defs/${lib}.def
        COMMENT "Generating ${lib}.lib import library")
    list(APPEND MQ_IMPORT_LIBS ${MQ_IMPORT_DIR}/${lib}.lib)
endforeach()
add_custom_target(mq_import_libs DEPENDS ${MQ_IMPORT_LIBS})

add_library(MQ2RmlUi SHARED
    src/MQ2RmlUi.cpp
    src/RenderInterface_DX9.cpp
    src/RenderInterface_DX9.h
    src/mq_api.h)
add_dependencies(MQ2RmlUi mq_import_libs)

target_include_directories(MQ2RmlUi PRIVATE
    src
    third_party/imgui
    third_party/stb)
target_compile_definitions(MQ2RmlUi PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(MQ2RmlUi PRIVATE /W3 /utf-8 /EHsc /permissive-)
target_link_libraries(MQ2RmlUi PRIVATE RmlUi::RmlUi ${MQ_IMPORT_LIBS} d3d9)
set_target_properties(MQ2RmlUi PROPERTIES PREFIX "" OUTPUT_NAME "MQ2RmlUi")

# Offline renderer check: draws an RML document with the same D3D9 backend and saves PNGs.
add_executable(rml_preview tools/rml_preview.cpp src/RenderInterface_DX9.cpp)
target_include_directories(rml_preview PRIVATE src third_party/stb)
target_compile_definitions(rml_preview PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(rml_preview PRIVATE /W3 /utf-8 /EHsc)
target_link_libraries(rml_preview PRIVATE RmlUi::RmlUi d3d9)
