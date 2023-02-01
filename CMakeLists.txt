# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
# 并包含子项目。
#
cmake_minimum_required (VERSION 3.21)

project("Ra3Profiler")

function(APPLY_COMMON_CONFIGURATION TARGET_NAME)
    # Macros
    target_compile_definitions(${TARGET_NAME} PRIVATE
        "UNICODE=1"
        "_UNICODE=1"
        "WIN32_LEAN_AND_MEAN=1"
        "WINVER=_WIN32_WINNT_WIN7" # 把最低支持的操作系统设为 Windows 7
        "_WIN32_WINNT=_WIN32_WINNT_WIN7" # 把最低支持的操作系统设为 Windows 7
        "NOMINMAX"
    )
    # UTF-8 and debug
    target_compile_options(${TARGET_NAME} PRIVATE
        "$<$<CXX_COMPILER_ID:MSVC>:/utf-8>"
        "$<$<CXX_COMPILER_ID:MSVC>:$<$<CONFIG:Debug>:/ZI>>"
    )
    target_link_options(${TARGET_NAME} PRIVATE
        "$<$<CXX_COMPILER_ID:MSVC>:$<$<CONFIG:Debug>:/SAFESEH:NO>>"
    )
    # C++23
    target_compile_features(${TARGET_NAME} PUBLIC cxx_std_23)
    # Static link and LTO
    set_target_properties(${TARGET_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        INTERPROCEDURAL_OPTIMIZATION "$<$<CONFIG:Debug>:FALSE:TRUE>"
    )
endfunction()

add_executable("Injector")
add_subdirectory("Injector")
apply_common_configuration("Injector")

add_library("Ra3Profiler" SHARED)
add_subdirectory("Ra3Profiler")
apply_common_configuration("Ra3Profiler")