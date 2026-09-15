cmake_minimum_required(VERSION 3.20)
project(FiveMDumper VERSION 1.0.0 LANGUAGES CXX)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler options
if(MSVC)
    add_compile_options(/W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra)
endif()

# Prevent Windows headers from polluting std::min/std::max and the ERROR macro
add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX NOGDI)

# No external packages needed:
#  - HTTP   : WinHTTP   (system, linked below)
#  - AES    : BCrypt    (system, linked below)
#  - SHA256 : own impl  (src/crypto/Sha256.cpp)
#  - ChaCha20: own impl (src/crypto/ChaCha20.cpp)
#  - JSON   : own impl  (src/utils/Json.cpp)

# ---- Embedded payload: the EXE ships alone (extracted to %LOCALAPPDATA%) ----
# Entire Bin/ (minus CitiTest build artifacts) so Unpacker.exe's full FXServer
# component stack loads from the extracted payload, plus the VC++ runtime DLLs
# it imports, so the target machine needs no redistributable install.
set(DUMPER_PAYLOAD_ITEMS "")
file(GLOB _bin_top LIST_DIRECTORIES false "${CMAKE_SOURCE_DIR}/Bin/*")
foreach(_f IN LISTS _bin_top)
    get_filename_component(_n "${_f}" NAME)
    if(_n MATCHES "^(\\..*|CitiTest\\.(exe|exp|lib)|.*\\.(pdb|ilk|obj|log))$")
        continue()
    endif()
    list(APPEND DUMPER_PAYLOAD_ITEMS "Bin/${_n}|${_f}")
endforeach()
file(GLOB_RECURSE _bin_citizen LIST_DIRECTORIES false "${CMAKE_SOURCE_DIR}/Bin/citizen/*")
foreach(_f IN LISTS _bin_citizen)
    file(TO_CMAKE_PATH "${_f}" _fc)
    if(_fc MATCHES "/system_resources/")
        continue()
    endif()
    file(RELATIVE_PATH _rel "${CMAKE_SOURCE_DIR}" "${_f}")
    list(APPEND DUMPER_PAYLOAD_ITEMS "${_rel}|${_f}")
endforeach()

get_filename_component(_d1 "${CMAKE_CXX_COMPILER}" DIRECTORY)
get_filename_component(_d2 "${_d1}" DIRECTORY)
get_filename_component(_d3 "${_d2}" DIRECTORY)
get_filename_component(_msvc_root "${_d3}" DIRECTORY)
file(GLOB _vcrt_dirs "${_msvc_root}/redist/MSVC/*/x64/Microsoft.VC*")
foreach(_dll msvcp140.dll msvcp140_2.dll msvcp140_atomic_wait.dll vcruntime140.dll vcruntime140_1.dll)
    set(_src "")
    foreach(_dir IN LISTS _vcrt_dirs)
        if(EXISTS "${_dir}/${_dll}")
            set(_src "${_dir}/${_dll}")
            break()
        endif()
    endforeach()
    if(NOT _src AND EXISTS "$ENV{SystemRoot}/System32/${_dll}")
        set(_src "$ENV{SystemRoot}/System32/${_dll}")
    endif()
    if(NOT _src)
        message(FATAL_ERROR "VC runtime DLL not found for embedding: ${_dll}")
    endif()
    list(APPEND DUMPER_PAYLOAD_ITEMS "Bin/${_dll}|${_src}")
endforeach()
list(APPEND DUMPER_PAYLOAD_ITEMS
    "Tools/Decompile/unluac54.jar|${CMAKE_SOURCE_DIR}/Tools/Decompile/unluac54.jar")

set(_rc_entries "")
set(_manifest_entries "")
set(_stamp_input "")
set(_idx 0)
foreach(pair IN LISTS DUMPER_PAYLOAD_ITEMS)
    string(FIND "${pair}" "|" _sep REVERSE)
    string(SUBSTRING "${pair}" 0 ${_sep} _name)
    math(EXPR _srcpos "${_sep} + 1")
    string(SUBSTRING "${pair}" ${_srcpos} -1 _src)
    if(NOT EXISTS "${_src}")
        message(FATAL_ERROR "Payload file missing: ${_name} (${_src})")
    endif()
    file(SHA256 "${_src}" _sha)
    file(SIZE "${_src}" _size)
    if(_size EQUAL 0)
        message(STATUS "Payload: skipping empty file ${_name}")
        continue()
    endif()
    file(TO_NATIVE_PATH "${_src}" _nat)
    string(REPLACE "\\" "\\\\" _nat "${_nat}")
    math(EXPR _resid "${_idx} + 101")
    string(APPEND _rc_entries "${_resid} RCDATA \"${_nat}\"\n")
    string(APPEND _manifest_entries "{\"${_name}\", ${_resid}, ${_size}, \"${_sha}\"},\\\n")
    string(APPEND _stamp_input "${_sha}")
    math(EXPR _idx "${_idx} + 1")
endforeach()
string(SHA256 _payload_stamp "${_stamp_input}")

file(WRITE "${CMAKE_BINARY_DIR}/payload.rc" "${_rc_entries}")
file(WRITE "${CMAKE_BINARY_DIR}/payload_manifest_gen.h"
    "#pragma once\n#define FIVEM_PAYLOAD_STAMP \"${_payload_stamp}\"\n#define FIVEM_PAYLOAD_ITEMS {\\\n${_manifest_entries}}\n")

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_BINARY_DIR})

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(fivem_dumper ${SOURCES} "${CMAKE_BINARY_DIR}/payload.rc")

target_link_libraries(fivem_dumper
    PRIVATE
    winhttp
    bcrypt
    ws2_32
    advapi32
    shell32
)
