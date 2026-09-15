cmake_minimum_required(VERSION 3.25)
project(krypto_tool LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)

# Tell CMake to use MSYS2's pkg-config to find GTK4
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED gtk4)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

add_executable(krypto_tool krypto_tool.cpp)

# Include directories for GTK and OpenSSL
target_include_directories(krypto_tool PRIVATE ${GTK4_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Link the libraries
target_link_libraries(krypto_tool PRIVATE ${GTK4_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)

# Required for GTK on Windows to prevent console flashing if you make it a GUI app later
if(WIN32)
    target_link_options(krypto_tool PRIVATE "-mwindows")
endif()