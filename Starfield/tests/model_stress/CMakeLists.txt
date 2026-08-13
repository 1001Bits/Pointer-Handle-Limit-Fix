cmake_minimum_required(VERSION 3.23)

project(StarfieldHandleModelStress LANGUAGES CXX)

add_executable(StarfieldHandleModelStress main.cpp)
target_compile_features(StarfieldHandleModelStress PRIVATE cxx_std_23)
target_compile_definitions(StarfieldHandleModelStress PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN)

if(MSVC)
    target_compile_options(StarfieldHandleModelStress PRIVATE
        /O2
        /W4
        /permissive-
        /Zc:__cplusplus)
endif()
