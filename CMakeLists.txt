cmake_minimum_required(VERSION 3.15)
project(Omamori VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

# Platform detection
if(WIN32)
    set(OMAMORI_PLATFORM "Windows")
    add_definitions(-DOMAMORI_PLATFORM_WINDOWS)
elseif(UNIX AND NOT APPLE)
    set(OMAMORI_PLATFORM "Linux")
    add_definitions(-DOMAMORI_PLATFORM_LINUX)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

message(STATUS "Building Omamori for ${OMAMORI_PLATFORM}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Common includes
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/common/include
)

# Platform-specific library
if(WIN32)
    # Windows library
    add_library(Omamori
        windows/src/internal.cpp
        windows/src/antidebug.cpp
        windows/src/antidump.cpp
        windows/src/antivm.cpp
        windows/src/syscall.cpp
        windows/src/memory_encryption.cpp
    )
    
    target_include_directories(Omamori PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/windows/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    
    # Windows-specific compile definitions
    target_compile_definitions(Omamori PRIVATE
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    
    # Link Windows libraries
    target_link_libraries(Omamori PRIVATE
        ntdll
    )
    
    # Compiler-specific flags for Windows
    if(MSVC)
        target_compile_options(Omamori PRIVATE
            /W4
            /WX-
            /permissive-
            /GR-  # Disable RTTI
        )
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(Omamori PRIVATE
            -Wall -Wextra -Wpedantic
            -fno-rtti
            -fno-exceptions
        )
    endif()
    
elseif(UNIX)
    # Linux library
    add_library(Omamori
        linux/src/antidebug.cpp
        linux/src/antidump.cpp
        linux/src/antivm.cpp
        linux/src/memory_encryption.cpp
    )
    
    target_include_directories(Omamori PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/linux/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    
    # Link Linux libraries
    target_link_libraries(Omamori PRIVATE
        pthread
        dl
    )
    
    # Compiler flags for Linux
    target_compile_options(Omamori PRIVATE
        -Wall -Wextra -Wpedantic
        -fno-rtti
        -fno-exceptions
        -fPIC
    )
    
    # Security hardening flags
    target_compile_options(Omamori PRIVATE
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
    )
    
    target_link_options(Omamori PRIVATE
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
    )
endif()

# Build examples
if(BUILD_EXAMPLES)
    if(WIN32)
        add_executable(omamori_example_windows
            examples/windows_example.cpp
        )
        target_link_libraries(omamori_example_windows PRIVATE Omamori)
        
        # Set subsystem to console
        if(MSVC)
            set_target_properties(omamori_example_windows PROPERTIES
                LINK_FLAGS "/SUBSYSTEM:CONSOLE"
            )
        endif()
        
    elseif(UNIX)
        add_executable(omamori_example_linux
            examples/linux_example.cpp
        )
        target_link_libraries(omamori_example_linux PRIVATE Omamori)
        
        # Add anti-attach test
        add_executable(omamori_anti_attach_test
            examples/anti_attach_test.cpp
        )
        target_link_libraries(omamori_anti_attach_test PRIVATE Omamori)
        
        # Add anti-dump verification test
        add_executable(omamori_verify_antidump
            examples/verify_antidump.cpp
        )
        target_link_libraries(omamori_verify_antidump PRIVATE Omamori)
        
        # Strip symbols in release builds
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            add_custom_command(TARGET omamori_example_linux POST_BUILD
                COMMAND ${CMAKE_STRIP} $<TARGET_FILE:omamori_example_linux>
                COMMENT "Stripping symbols from example binary"
            )
        endif()
    endif()
endif()

# Tests
if(BUILD_TESTS)
    if(WIN32)
        add_executable(omamori_test_windows tests/test_windows.cpp)
        target_link_libraries(omamori_test_windows PRIVATE Omamori)
        
        if(CMAKE_BUILD_TYPE MATCHES "Release")
            target_compile_options(omamori_test_windows PRIVATE
                $<$<CXX_COMPILER_ID:MSVC>:/O2 /Oi>
                $<$<CXX_COMPILER_ID:GNU,Clang>:-O3>
            )
        endif()
    elseif(UNIX)
        add_executable(omamori_test_linux tests/test_linux.cpp)
        target_link_libraries(omamori_test_linux PRIVATE Omamori)
        
        if(CMAKE_BUILD_TYPE MATCHES "Release")
            target_compile_options(omamori_test_linux PRIVATE -O3)
            
            add_custom_command(TARGET omamori_test_linux POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:omamori_test_linux>
                COMMENT "Stripping symbols from test binary"
            )
        endif()
    endif()
    
    # UPX stub protection example/test
    if(UNIX)
        add_executable(omamori_upx_stub_test
            examples/upx_stub_protection.cpp
        )
        target_compile_definitions(omamori_upx_stub_test PRIVATE BUILD_TEST)
        target_link_libraries(omamori_upx_stub_test PRIVATE Omamori)
        target_compile_options(omamori_upx_stub_test PRIVATE -Os)
        set_target_properties(omamori_upx_stub_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        
        # Memory encryption test
        add_executable(omamori_memory_encryption_test
            examples/test_memory_encryption.cpp
        )
        target_link_libraries(omamori_memory_encryption_test PRIVATE Omamori)
        set_target_properties(omamori_memory_encryption_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        
        # License protection example
        add_executable(omamori_license_example
            examples/example_license_protection.cpp
        )
        target_link_libraries(omamori_license_example PRIVATE Omamori)
        set_target_properties(omamori_license_example PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        
        # Selective protection example
        add_executable(omamori_selective_protection
            examples/selective_protection.cpp
        )
        target_link_libraries(omamori_selective_protection PRIVATE Omamori)
        set_target_properties(omamori_selective_protection PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        
        # Anti-VM test (Linux)
        add_executable(omamori_antivm_test_linux
            examples/test_antivm_linux.cpp
        )
        target_link_libraries(omamori_antivm_test_linux PRIVATE Omamori)
        set_target_properties(omamori_antivm_test_linux PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endif()
    
    # Anti-VM test (Windows only)
    if(WIN32 AND BUILD_EXAMPLES)
        add_executable(omamori_antivm_test_windows
            examples/test_antivm_windows.cpp
        )
        target_link_libraries(omamori_antivm_test_windows PRIVATE Omamori)
        set_target_properties(omamori_antivm_test_windows PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endif()
endif()

# Installation
install(TARGETS Omamori
    EXPORT OmamoriTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install headers
if(WIN32)
    install(DIRECTORY windows/include/ DESTINATION include/omamori/windows)
elseif(UNIX)
    install(DIRECTORY linux/include/ DESTINATION include/omamori/linux)
endif()

install(DIRECTORY common/include/ DESTINATION include/omamori/common)
install(DIRECTORY include/ DESTINATION include/omamori)

# Export targets
install(EXPORT OmamoriTargets
    FILE OmamoriTargets.cmake
    NAMESPACE Omamori::
    DESTINATION lib/cmake/Omamori
)

# Create package config
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/OmamoriConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/OmamoriConfig.cmake
    INSTALL_DESTINATION lib/cmake/Omamori
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/OmamoriConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/OmamoriConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/OmamoriConfigVersion.cmake
    DESTINATION lib/cmake/Omamori
)

# Print summary
message(STATUS "")
message(STATUS "Omamori Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Platform: ${OMAMORI_PLATFORM}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "")
