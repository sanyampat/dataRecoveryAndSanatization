cmake_minimum_required(VERSION 3.15)
project(SIH_SanitizerOS VERSION 1.0 LANGUAGES CXX)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories for core modules
# (device/ added directly because apps/device-test/main.cpp does
#  #include "DriveManager.h" with no path prefix)
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/device)

# HashEngine (acquisition module) uses OpenSSL's EVP API for SHA-256
find_package(OpenSSL REQUIRED)

# Collect all core source files
set(CORE_SOURCES
    device/DriveManager.cpp
    sanitization/SanitizationEngine.cpp
    sanitization/HddSanitizer.cpp
    sanitization/NvmeSanitizer.cpp
    sanitization/SataSanitizer.cpp
    sanitization/Verification.cpp
    acquisition/HashEngine.cpp
    acquisition/WriteProtection.cpp
    acquisition/DiskImager.cpp
    acquisition/AcquisitionManager.cpp
    recovery/FileCarver.cpp
    recovery/FileValidator.cpp
    recovery/ConfidenceScorer.cpp
    recovery/FileClassifier.cpp
)

# Create the core static library
add_library(sih_core STATIC ${CORE_SOURCES})

# sih_core now needs OpenSSL for HashEngine
target_link_libraries(sih_core PRIVATE OpenSSL::Crypto)

# Build the device test application
add_executable(device-test apps/device-test/main.cpp)

# Link the test app against the core library and pthread (often required for system calls)
target_link_libraries(device-test PRIVATE sih_core pthread)

# Build the hash engine test application
add_executable(hashengine-test apps/hashengine-test/main.cpp)
target_link_libraries(hashengine-test PRIVATE sih_core pthread)

# Build the acquisition test application (write-protect -> image -> hash)
add_executable(acquisition-test apps/acquisition-test/main.cpp)
target_link_libraries(acquisition-test PRIVATE sih_core pthread)

# Build the recovery test application (carve -> validate -> score -> classify)
add_executable(recovery-test apps/recovery-test/main.cpp)
target_link_libraries(recovery-test PRIVATE sih_core pthread)
