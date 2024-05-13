cmake_minimum_required(VERSION 3.10)
project(TpmEncrypt)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Ensure we can find pkg-config
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

# Find TSS2 with pkg-config
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-fapi)

# Include directories
include_directories(include ${TSS2_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Source files
set(SOURCES src/data_encrypt.cpp src/data_decrypt.cpp src/common.cpp)

# Create shared library
add_library(tpm_encrypt SHARED ${SOURCES})

# Link external dependencies
target_link_libraries(tpm_encrypt ${OPENSSL_LIBRARIES} ${TSS2_LIBRARIES})

## Demo App ##

# Main executable
add_executable(demo_exe src/main.cpp)

# Link the library to the executable
target_link_libraries(demo_exe tpm_encrypt)