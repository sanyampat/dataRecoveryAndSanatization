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

# Sleuth Kit (libtsk) — used throughout recovery/ for image I/O
# (tsk_img_open_sing / tsk_img_read / tsk_img_close / tsk_error_print).
# libtsk-dev ships no CMake config package, so locate it manually and wrap
# it in a proper IMPORTED target: PUBLIC usage requirements on an IMPORTED
# target (the library file + its include dir) propagate reliably to every
# executable that links sih_core, which a raw path passed to
# target_link_libraries does not always do consistently.
find_library(TSK_LIBRARY NAMES tsk)
if(NOT TSK_LIBRARY)
    message(FATAL_ERROR
        "libtsk not found. Confirm libtsk-dev is installed "
        "(expected e.g. /usr/lib/x86_64-linux-gnu/libtsk.so).")
endif()

find_path(TSK_INCLUDE_DIR NAMES tsk/libtsk.h)

add_library(tsk::tsk UNKNOWN IMPORTED)
set_target_properties(tsk::tsk PROPERTIES
    IMPORTED_LOCATION "${TSK_LIBRARY}"
)
if(TSK_INCLUDE_DIR)
    set_target_properties(tsk::tsk PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${TSK_INCLUDE_DIR}"
    )
endif()

# Collect all core source files
set(CORE_SOURCES
    device/DriveManager.cpp
    sanitization/SanitizationEngine.cpp
    sanitization/DeviceCapabilityProbe.cpp
    sanitization/NvmeSanitizer.cpp
    sanitization/AtaSanitizer.cpp
    sanitization/ScsiSanitizer.cpp
    sanitization/GenericBlockSanitizer.cpp
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

set_target_properties(sih_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# sih_core now needs OpenSSL for HashEngine
target_link_libraries(sih_core PRIVATE OpenSSL::Crypto)

# PUBLIC (not PRIVATE): sih_core is a STATIC library, so it has no link
# step of its own — TSK only actually gets pulled onto a linker command
# line when something that needs its symbols (recovery-test) links
# sih_core. PRIVATE would stop the dependency at sih_core and it would
# never reach recovery-test's link line at all.
target_link_libraries(sih_core PUBLIC tsk::tsk)

# Build the device test application
add_executable(device-test apps/device-test/main.cpp)

# Link the test app against the core library and pthread (often required for system calls)
target_link_libraries(device-test PRIVATE sih_core pthread)

# Build the hash engine test application
# NOTE: apps/hashengine-test/main.cpp does not exist in this checkout, so
# this target is disabled to keep `make` from failing on the whole project.
# Re-enable once that file is added back.
# add_executable(hashengine-test apps/hashengine-test/main.cpp)
# target_link_libraries(hashengine-test PRIVATE sih_core pthread)

# Build the acquisition test application (write-protect -> image -> hash)
add_executable(acquisition-test apps/acquisition-test/main.cpp)
target_link_libraries(acquisition-test PRIVATE sih_core pthread)

# Build the sanitizer CLI application (drive picker -> dry-run sanitize)
add_executable(sanitizer apps/sanitizer/main.cpp)
target_link_libraries(sanitizer PRIVATE sih_core pthread)

# Build the recovery test application (carve -> validate -> score -> classify)
add_executable(recovery-test apps/recovery-test/main.cpp)
target_link_libraries(recovery-test PRIVATE sih_core pthread)

# Sanitizer UI (drive picker -> sanitize selected/all -> confirm -> log).
# Uses FLTK for a small footprint that's easy to ship inside the live-OS
# rootfs. Guarded: if FLTK isn't installed yet, the rest of the project
# still configures and builds.
#    Debian/Ubuntu: sudo apt install libfltk1.3-dev
#    Arch:         sudo pacman -S fltk
find_package(FLTK)

if(FLTK_FOUND)

    add_executable(
        sanitizer-ui
        apps/sanitizer-ui/main.cpp
    )

    target_include_directories(
        sanitizer-ui
        PRIVATE
        /usr/include/cairo
        ${FLTK_INCLUDE_DIR}
    )

    target_link_libraries(
        sanitizer-ui
        PRIVATE
        sih_core
        ${FLTK_LIBRARIES}
        pthread
    )

else()

    message(
        STATUS
        "FLTK not found - skipping sanitizer-ui target "
        "(install fltk to build it)"
    )

endif()

# ------------------------------------------------------------
# Python C++ Sanitizer Module
# ------------------------------------------------------------

find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(cpp_sanitizer
    UI/sanitizer_ui.cpp
)

target_link_libraries(cpp_sanitizer
    PRIVATE
    sih_core
)

target_include_directories(cpp_sanitizer
    PRIVATE
    ${CMAKE_SOURCE_DIR}
)

set_target_properties(cpp_sanitizer PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY
    ${CMAKE_SOURCE_DIR}/UI
)