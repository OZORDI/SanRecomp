project("SanRecompLib")

add_compile_options(
    -fno-strict-aliasing
)

if (WIN32)
    add_compile_options(/fp:strict)
else()
    add_compile_options(-ffp-model=strict)
endif()

target_compile_definitions(XenonRecomp PRIVATE 
    XENON_RECOMP_CONFIG_FILE_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/config/GTA5.toml\"
    XENON_RECOMP_HEADER_FILE_PATH=\"${SAN_RECOMP_TOOLS_ROOT}/XenonRecomp/XenonUtils/ppc_context.h\")

set(SAN_RECOMP_PPC_RECOMPILED_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_config.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_context.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_func_mapping.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_recomp_shared.h"
)

foreach(i RANGE 0 545)
    list(APPEND SAN_RECOMP_PPC_RECOMPILED_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_recomp.${i}.cpp")
endforeach()

# XenonRecomp custom command disabled - PPC files already generated
# To regenerate, run manually:
#   cd SanRecompLib/config && /path/to/XenonRecomp ./GTA5.toml ../../SanRecomp/cpu/ppc_context.h
#
# add_custom_command(
#     OUTPUT 
#         ${SAN_RECOMP_PPC_RECOMPILED_SOURCES}
#     COMMAND 
#         $<TARGET_FILE:XenonRecomp>
#     DEPENDS 
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/default.xex"
#         "${CMAKE_CURRENT_SOURCE_DIR}/config/GTA5.toml"
#     USES_TERMINAL
# )

# NOTE: GTA V shader handling is different from Sonic '06
# The shader.arc/shader_lt.arc extraction is disabled for GTA V
# A stub shader_cache.cpp is used until GTA V shader extraction is implemented
#
# Original Sonic '06 shader extraction (disabled):
# add_custom_command(
#     OUTPUT
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/shader"
#     COMMAND
#         $<TARGET_FILE:u8extract> "${CMAKE_CURRENT_SOURCE_DIR}/private/shader.arc" "${CMAKE_CURRENT_SOURCE_DIR}/private/shader"
#     COMMAND
#         $<TARGET_FILE:u8extract> "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_lt.arc" "${CMAKE_CURRENT_SOURCE_DIR}/private/shader"
#     DEPENDS
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/shader.arc"
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_lt.arc"
# )

set(XENOS_RECOMP_ROOT "${SAN_RECOMP_TOOLS_ROOT}/XenosRecomp/XenosRecomp")
set(XENOS_RECOMP_INCLUDE "${XENOS_RECOMP_ROOT}/shader_common.h")

target_compile_definitions(XenosRecomp PRIVATE 
    XENOS_RECOMP_INPUT=\"${CMAKE_CURRENT_SOURCE_DIR}/private/shader\" 
    XENOS_RECOMP_OUTPUT=\"${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp\"
    XENOS_RECOMP_INCLUDE_INPUT=\"${XENOS_RECOMP_INCLUDE}\"
    SAN_RECOMP
)

file(GLOB XENOS_RECOMP_SOURCES 
    "${XENOS_RECOMP_ROOT}/*.h"
    "${XENOS_RECOMP_ROOT}/*.cpp"
)

# NOTE: Shader recompilation disabled for GTA V
# Using stub shader_cache.cpp until GTA V shader extraction is implemented
#
# add_custom_command(
#     OUTPUT 
#         "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp"
#     COMMAND
#         $<TARGET_FILE:XenosRecomp>
#     DEPENDS 
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/shader"
#         ${XENOS_RECOMP_SOURCES}
#         ${XENOS_RECOMP_INCLUDE}
#     USES_TERMINAL
# )

add_library(SanRecompLib
    ${SAN_RECOMP_PPC_RECOMPILED_SOURCES}
    "ppc/ppc_indirect.cpp"
    "shader/shader_cache.h"
    "shader/shader_cache.cpp"
)

target_include_directories(SanRecompLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(SanRecompLib PRIVATE "${SAN_RECOMP_TOOLS_ROOT}/XenonRecomp/thirdparty/simde")
target_precompile_headers(SanRecompLib PUBLIC "ppc/ppc_recomp_shared.h")
