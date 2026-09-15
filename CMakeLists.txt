cmake_minimum_required(VERSION 3.20)
project(FiveMDumper VERSION 1.0.0 LANGUAGES CXX)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler options
if(MSVC)
    add_compile_options(/W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS)
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

include_directories(${CMAKE_SOURCE_DIR}/src)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(fivem_dumper ${SOURCES})

target_link_libraries(fivem_dumper
    PRIVATE
    winhttp
    bcrypt
    ws2_32
    advapi32
    shell32
)
