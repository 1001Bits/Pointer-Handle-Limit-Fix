cmake_minimum_required(VERSION 3.23)

set(NAME "StarfieldHandleLiveStress")

if(NOT DEFINED VCPKG_ROOT AND DEFINED ENV{VCPKG_ROOT})
    set(VCPKG_ROOT "$ENV{VCPKG_ROOT}")
endif()
if(NOT DEFINED VCPKG_ROOT)
    message(FATAL_ERROR "VCPKG_ROOT is required")
endif()

set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
set(VCPKG_TARGET_TRIPLET "x64-windows-static-md" CACHE STRING "")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL" CACHE STRING "")

project(${NAME} VERSION 1.0.0 LANGUAGES CXX)

set(CommonLibSFPath "" CACHE PATH "Path to a CommonLibSF checkout")
if(NOT CommonLibSFPath AND DEFINED ENV{COMMONLIBSF_PATH})
    set(CommonLibSFPath "$ENV{COMMONLIBSF_PATH}")
endif()
if(NOT EXISTS "${CommonLibSFPath}/CMakeLists.txt")
    message(FATAL_ERROR
        "Set CommonLibSFPath or COMMONLIBSF_PATH to a CommonLibSF checkout")
endif()

add_subdirectory("${CommonLibSFPath}" CommonLibSF EXCLUDE_FROM_ALL)
find_package(spdlog REQUIRED CONFIG)

add_library(${NAME} SHARED src/main.cpp)
target_compile_features(${NAME} PRIVATE cxx_std_23)
target_link_libraries(${NAME} PRIVATE CommonLibSF::CommonLibSF)
target_compile_definitions(${NAME} PRIVATE
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

if(MSVC)
    target_compile_options(${NAME} PRIVATE /MP /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /Zi)
    target_link_options(${NAME} PRIVATE /DEBUG /OPT:REF /OPT:ICF)
endif()
