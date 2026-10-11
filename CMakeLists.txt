cmake_minimum_required (VERSION 3.29)

set(SAN_RECOMP_THIRDPARTY_ROOT ${CMAKE_SOURCE_DIR}/thirdparty)
set(SAN_RECOMP_TOOLS_ROOT ${CMAKE_SOURCE_DIR}/tools)
set(CMAKE_CXX_STANDARD 23)
set(BUILD_SHARED_LIBS OFF)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Check source prerequisites before project() enters the vcpkg toolchain.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/DependencyPatches.cmake")
san_require_dependency_sources("${CMAKE_CURRENT_SOURCE_DIR}")
if(APPLE AND NOT CMAKE_TOOLCHAIN_FILE)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindHostLLVM.cmake")
endif()
project("SanRecomp-ALL")

# Reproduce the source fixes carried for pinned upstream dependencies.
san_apply_dependency_patches("${CMAKE_CURRENT_SOURCE_DIR}")

set(SAN_RECOMP_GRAINE_MAC OFF)
if(APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS" AND
   (NOT DEFINED SAN_RECOMP_TARGET_PLATFORM OR
    SAN_RECOMP_TARGET_PLATFORM STREQUAL "desktop"))
    set(SAN_RECOMP_GRAINE_MAC ON)
endif()

if(SAN_RECOMP_GRAINE_MAC)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckMacOSToolchain.cmake")
endif()

# Android consumes the same pure Graine RexGlue application as macOS; the
# legacy SanRecomp/ tree is not built for it.
set(SAN_RECOMP_GRAINE_ANDROID OFF)
if(ANDROID)
    set(SAN_RECOMP_GRAINE_ANDROID ON)
endif()

if(NOT SAN_RECOMP_GRAINE_MAC)
    add_compile_definitions(FMT_USE_CONSTEVAL=0)
endif()

# ─── vcpkg check (desktop platforms only) ──────────────────────────────────
if(NOT SAN_RECOMP_GRAINE_MAC AND
   (NOT DEFINED SAN_RECOMP_TARGET_PLATFORM OR
    SAN_RECOMP_TARGET_PLATFORM STREQUAL "desktop"))
    if(NOT DEFINED ENV{VCPKG_ROOT})
        message(FATAL_ERROR "VCPKG_ROOT is not defined! Set it or use a platform-specific preset.")
    endif()
endif()
# ────────────────────────────────────────────────────────────────────────────

# ─── Cross-Platform Target Selection ───────────────────────────────────────
if(NOT DEFINED SAN_RECOMP_TARGET_PLATFORM)
    set(SAN_RECOMP_TARGET_PLATFORM "desktop" CACHE STRING
        "Target platform: desktop | ios | android | ps4 | switch")
endif()
message(STATUS "Target platform: ${SAN_RECOMP_TARGET_PLATFORM}")

if(APPLE)
    set(SAN_IOS_DEVELOPMENT_TEAM "" CACHE STRING "Apple development team ID for iOS signing.")
    set(SAN_IOS_BUNDLE_IDENTIFIER "com.sanrecomp" CACHE STRING "Bundle identifier for iOS builds.")
    set(SAN_IOS_PROVISIONING_PROFILE "" CACHE STRING "Optional iOS provisioning profile specifier.")
    set(SAN_MACOS_BUNDLE_IDENTIFIER "OZORDI.SanRecomp" CACHE STRING "Bundle identifier for macOS builds.")
    set(SAN_MACOS_CODE_SIGN_IDENTITY "" CACHE STRING "Optional macOS codesign identity for entitlement signing.")
endif()

# ─── Build-time Asset Path (GTA V Xbox 360 Specifics) ───────────────────────
set(SAN_RECOMP_EMBEDDED_GAME_PATH
    "${CMAKE_SOURCE_DIR}/tools/local_game_payload"
    CACHE PATH "Path to the staged GTA V Xbox 360 game files for embedded builds")
if(DEFINED ENV{GAME_PATH})
    set(SAN_RECOMP_EMBEDDED_GAME_PATH "$ENV{GAME_PATH}")
    message(STATUS "GAME_PATH env var set — using: ${SAN_RECOMP_EMBEDDED_GAME_PATH}")
endif()

option(SAN_RECOMP_ANDROID_RUNTIME_ASSETS
    "Android: expect the game payload to be supplied at runtime (skip CMake-time validation)"
    OFF)

if(NOT SAN_RECOMP_TARGET_PLATFORM STREQUAL "desktop")
    message(STATUS "Embedded game path: ${SAN_RECOMP_EMBEDDED_GAME_PATH}")

    if(SAN_RECOMP_TARGET_PLATFORM STREQUAL "android" AND SAN_RECOMP_ANDROID_RUNTIME_ASSETS)
        message(STATUS
            "Android: SAN_RECOMP_ANDROID_RUNTIME_ASSETS=ON — skipping build-time\n"
            "         game-file validation. The Activity's folder-picker flow is\n"
            "         expected to hand the path to the native runtime via\n"
            "         Java_com_sanrecomp_SanSDLActivity_nativeSetGameRoot.")
    else()
        if(NOT EXISTS "${SAN_RECOMP_EMBEDDED_GAME_PATH}")
            message(FATAL_ERROR
                "SAN_RECOMP_EMBEDDED_GAME_PATH does not exist:\n"
                "  ${SAN_RECOMP_EMBEDDED_GAME_PATH}\n"
                "Set the GAME_PATH environment variable to your extracted game directory,\n"
                "or populate tools/local_game_payload/, or pass "
                "-DSAN_RECOMP_EMBEDDED_GAME_PATH=... to CMake.")
        endif()

        # Validate required GTA V Xbox 360 files instead of GTA IV ones
        foreach(_req_file default.xex common.rpf x360a.rpf)
            if(NOT EXISTS "${SAN_RECOMP_EMBEDDED_GAME_PATH}/${_req_file}")
                message(FATAL_ERROR
                    "Required game file missing from embedded payload:\n"
                    "  ${SAN_RECOMP_EMBEDDED_GAME_PATH}/${_req_file}")
            endif()
        endforeach()

        message(STATUS "Embedded payload validated successfully.")
    endif()

    # ── Manifest variables ────────────────────────────────────────────────
    set(SAN_PAYLOAD_GAME_VERSION "1.0.0")
    set(SAN_PAYLOAD_TU_VERSION   "")
    string(TIMESTAMP SAN_PAYLOAD_BUILD_TIMESTAMP "%s")

    configure_file(
        "${CMAKE_SOURCE_DIR}/SanRecomp/install/manifest.json.in"
        "${CMAKE_BINARY_DIR}/manifest.json"
        @ONLY)
endif()
# ────────────────────────────────────────────────────────────────────────────

if (APPLE AND NOT SAN_RECOMP_TARGET_PLATFORM STREQUAL "ps4")
    enable_language(OBJC OBJCXX)
endif()

if (CMAKE_OSX_ARCHITECTURES)
    set(SAN_RECOMP_ARCHITECTURE ${CMAKE_OSX_ARCHITECTURES})
elseif(CMAKE_SYSTEM_PROCESSOR)
    set(SAN_RECOMP_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
else()
    set(SAN_RECOMP_ARCHITECTURE ${CMAKE_HOST_SYSTEM_PROCESSOR})
endif()
string(TOLOWER "${SAN_RECOMP_ARCHITECTURE}" SAN_RECOMP_ARCHITECTURE)
message(STATUS "Detected architecture: ${SAN_RECOMP_ARCHITECTURE}")

if (SAN_RECOMP_ARCHITECTURE STREQUAL "x86_64" OR SAN_RECOMP_ARCHITECTURE STREQUAL "amd64")
    add_compile_options(
        -march=sandybridge
    )
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(_DEBUG)
endif()

option(USE_REXGLUE_RUNTIME "Use RexGlue SDK for runtime infrastructure" ON)

if(SAN_RECOMP_GRAINE_MAC)
    if(NOT USE_REXGLUE_RUNTIME)
        message(FATAL_ERROR "The macOS build requires the Graine RexGlue runtime")
    endif()

    message(STATUS "macOS: building the pure Graine RexGlue consumer")
    add_subdirectory("glue")
    return()
endif()

if(SAN_RECOMP_GRAINE_ANDROID)
    message(STATUS "Android: building the pure Graine RexGlue consumer")
    add_subdirectory("glue")
    return()
endif()

add_subdirectory(${SAN_RECOMP_THIRDPARTY_ROOT})

set(THIRDPARTY_ROOT ${CMAKE_SOURCE_DIR}/third_party)
if (NOT TARGET disasm)
    add_subdirectory(${THIRDPARTY_ROOT}/disasm ${CMAKE_BINARY_DIR}/_xbox_disasm)
endif()
if (NOT TARGET xbox_support)
    add_subdirectory(${THIRDPARTY_ROOT}/xbox_support ${CMAKE_BINARY_DIR}/_xbox_support)
endif()

# Dev tools bypass for mobile target
if(NOT DEFINED SAN_RECOMP_TARGET_PLATFORM OR SAN_RECOMP_TARGET_PLATFORM STREQUAL "desktop")
    add_subdirectory(${SAN_RECOMP_TOOLS_ROOT})
else()
    add_subdirectory(${SAN_RECOMP_TOOLS_ROOT}/liberty_debugger)
    set(XENOS_THIRDPARTY_ROOT ${SAN_RECOMP_TOOLS_ROOT}/XenosRecomp/thirdparty)
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_DICTBUILDER OFF CACHE BOOL "" FORCE)
    set(ZSTD_DISABLE_ASM ON CACHE BOOL "" FORCE)
    if (NOT TARGET libzstd_static)
        add_subdirectory(${XENOS_THIRDPARTY_ROOT}/zstd/build/cmake ${CMAKE_BINARY_DIR}/_zstd)
    endif()
    if (NOT TARGET xxHash::xxhash)
        set(XXHASH_BUILD_XXHSUM OFF CACHE BOOL "" FORCE)
        add_subdirectory(${XENOS_THIRDPARTY_ROOT}/xxHash/cmake_unofficial ${CMAKE_BINARY_DIR}/_xxhash)
    endif()
endif()

# RexGlue SDK integration
if(USE_REXGLUE_RUNTIME)
    add_subdirectory("glue")
endif()

# Include sub-projects for GTA V tree
add_subdirectory("SanRecompLib")
add_subdirectory("SanRecomp")
