cmake_minimum_required(VERSION 3.25)

set(NAME "StarfieldHandleCapRaise")
set(VERSION 1.0.1)

if(NOT DEFINED VCPKG_ROOT AND DEFINED ENV{VCPKG_ROOT})
    set(VCPKG_ROOT "$ENV{VCPKG_ROOT}")
endif()

if(DEFINED VCPKG_ROOT AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE
        "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
endif()
if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "x64-windows-static-md" CACHE STRING "")
endif()

project(${NAME} VERSION ${VERSION} LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "${NAME} requires the 64-bit MSVC toolchain")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "${NAME} must be built for x64")
endif()

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

set(SFHCR_SOURCES
    src/Configuration.cpp
    src/EngineAccess.cpp
    src/FormAttribution.cpp
    src/GenerationDiagnostic.cpp
    src/main.cpp
    src/PatchTransaction.cpp
    src/TableMonitor.cpp
)

set(SFHCR_HEADERS
    src/Configuration.h
    src/EngineAccess.h
    src/FormAttribution.h
    src/GenerationDiagnostic.h
    src/GenerationTracker.h
    src/HandleTable.h
    src/PatchTransaction.h
    src/RuntimeTypes.h
    src/TableMonitor.h
)

add_library(${NAME} SHARED ${SFHCR_SOURCES} ${SFHCR_HEADERS})
target_compile_features(${NAME} PRIVATE cxx_std_23)
target_compile_definitions(${NAME} PRIVATE
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)
target_compile_options(${NAME} PRIVATE
    /MP
    /W4
    /permissive-
    /utf-8
    /Zc:preprocessor
    /Zc:__cplusplus
)
target_link_libraries(${NAME} PRIVATE CommonLibSF::CommonLibSF)

set_target_properties(${NAME} PROPERTIES
    CXX_EXTENSIONS OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
)

set(SFHCR_PACKAGE_ROOT "${CMAKE_BINARY_DIR}/package")
set(SFHCR_PACKAGE_PLUGIN_DIR "${SFHCR_PACKAGE_ROOT}/SFSE/Plugins")
set(SFHCR_PACKAGE_ZIP
    "${CMAKE_BINARY_DIR}/PointerHandleLimitFix-v${PROJECT_VERSION}.zip")
file(MAKE_DIRECTORY "${SFHCR_PACKAGE_ROOT}")

add_custom_target(package_plugin
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${SFHCR_PACKAGE_PLUGIN_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:${NAME}>"
        "${SFHCR_PACKAGE_PLUGIN_DIR}/StarfieldHandleCapRaise.dll"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_SOURCE_DIR}/StarfieldHandleCapRaise.ini"
        "${SFHCR_PACKAGE_PLUGIN_DIR}/StarfieldHandleCapRaise.ini"
    COMMAND "${CMAKE_COMMAND}" -E tar cf
        "${SFHCR_PACKAGE_ZIP}"
        --format=zip
        "SFSE/Plugins/StarfieldHandleCapRaise.dll"
        "SFSE/Plugins/StarfieldHandleCapRaise.ini"
    WORKING_DIRECTORY "${SFHCR_PACKAGE_ROOT}"
    DEPENDS ${NAME} "${CMAKE_SOURCE_DIR}/StarfieldHandleCapRaise.ini"
    COMMENT "Staging Pointer Handle Limit Fix and creating the release ZIP"
    VERBATIM
)
