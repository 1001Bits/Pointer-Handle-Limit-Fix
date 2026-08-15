cmake_minimum_required(VERSION 3.25)

project(SkyrimHandleCapRaise VERSION 2.2.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "SkyrimHandleCapRaise requires the 64-bit MSVC toolchain")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "SkyrimHandleCapRaise must be built for x64")
endif()

set(SHCR_SOURCES
    src/Configuration.cpp
    src/EngineAccess.cpp
    src/EngineFixesConfig.cpp
    src/EngineFixesInterop.cpp
    src/FormAttribution.cpp
    src/GenerationDiagnostic.cpp
    src/Logging.cpp
    src/main.cpp
    src/PatchTransaction.cpp
    src/PluginPaths.cpp
    src/RuntimeDetection.cpp
    src/StressTest.cpp
    src/TableMonitor.cpp
)

set(SHCR_HEADERS
    src/Configuration.h
    src/EngineAccess.h
    src/EngineFixesConfig.h
    src/EngineFixesInterop.h
    src/FormAttribution.h
    src/GenerationDiagnostic.h
    src/GenerationTracker.h
    src/HandleTable.h
    src/Logging.h
    src/PatchTable.g.h
    src/PatchTransaction.h
    src/PluginPaths.h
    src/ReservedPlayerSlot.h
    src/RuntimeDetection.h
    src/RuntimeTypes.h
    src/StressTest.h
    src/TableMonitor.h
)

add_library(SkyrimHandleCapRaise SHARED ${SHCR_SOURCES} ${SHCR_HEADERS})

target_compile_features(SkyrimHandleCapRaise PRIVATE cxx_std_20)
target_compile_definitions(SkyrimHandleCapRaise PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_compile_options(SkyrimHandleCapRaise PRIVATE
    /W4
    /WX
    /permissive-
    /EHsc
    /utf-8
    /Zc:__cplusplus
)
target_link_libraries(SkyrimHandleCapRaise PRIVATE
    Bcrypt
    Ole32
    Shell32
    Version
)
target_link_options(SkyrimHandleCapRaise PRIVATE
    /Brepro
)

set_target_properties(SkyrimHandleCapRaise PROPERTIES
    CXX_EXTENSIONS OFF
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
)

set(SHCR_PACKAGE_DATA "${CMAKE_SOURCE_DIR}/package/Data")
set(SHCR_PACKAGE_PLUGIN_DIR "${SHCR_PACKAGE_DATA}/SKSE/Plugins")
set(SHCR_PACKAGE_ARCHIVE "${SHCR_PACKAGE_DATA}/Pointer Handle Limit Fix.zip")
set(SHCR_SOURCE_DATE_EPOCH "1704067200")
file(MAKE_DIRECTORY "${SHCR_PACKAGE_DATA}")

add_custom_target(package_plugin ALL
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${SHCR_PACKAGE_PLUGIN_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:SkyrimHandleCapRaise>"
        "${SHCR_PACKAGE_PLUGIN_DIR}/SkyrimHandleCapRaise.dll"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_SOURCE_DIR}/SkyrimHandleCapRaise.ini"
        "${SHCR_PACKAGE_PLUGIN_DIR}/SkyrimHandleCapRaise.ini"
    COMMAND "${CMAKE_COMMAND}" -E env
        "SOURCE_DATE_EPOCH=${SHCR_SOURCE_DATE_EPOCH}"
        "${CMAKE_COMMAND}" -E tar cf
        "${SHCR_PACKAGE_ARCHIVE}"
        --format=zip
        "SKSE/Plugins/SkyrimHandleCapRaise.dll"
        "SKSE/Plugins/SkyrimHandleCapRaise.ini"
    WORKING_DIRECTORY "${SHCR_PACKAGE_DATA}"
    DEPENDS SkyrimHandleCapRaise "${CMAKE_SOURCE_DIR}/SkyrimHandleCapRaise.ini"
    COMMENT "Staging the SKSE plugin and creating the release ZIP"
    VERBATIM
)
