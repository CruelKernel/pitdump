cmake_minimum_required(VERSION 3.12)

if (NOT DEFINED NDK_ROOT)
    if (DEFINED ENV{NDK_ROOT})
        set(NDK_ROOT "$ENV{NDK_ROOT}")
    else ()
        message(FATAL_ERROR "Please define NDK_ROOT to point to your NDK path!")
    endif ()
endif ()

# Set the tool chain file
set(CMAKE_TOOLCHAIN_FILE ${NDK_ROOT}/build/cmake/android.toolchain.cmake)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM latest)
set(ANDROID_STL none)
set(ANDROID_LD lld)

add_compile_options(-Wall -Wextra -pedantic -Werror)
option(SELF_PACK_EXECUTABLES "Self-pack executables." ON)

project(PitDump)

set(CMAKE_C_FLAGS_RELEASE "-O2 -flto")
set(ANDROID_PIE FALSE)
link_libraries("-static")

add_executable(pitdump pitdump.c)

if (CMAKE_BUILD_TYPE STREQUAL Release)
    add_custom_command(
        TARGET pitdump
        POST_BUILD
        COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" --strip-all pitdump
        COMMENT "Stripping the executables"
        VERBATIM
    )
    if (SELF_PACK_EXECUTABLES)
      include("${CMAKE_ROOT}/Modules/FindSelfPackers.cmake")
      if (SELF_PACKER_FOR_EXECUTABLE)
          add_custom_command(
              TARGET pitdump
              POST_BUILD
              COMMAND ${SELF_PACKER_FOR_EXECUTABLE} -9q ${SELF_PACKER_FOR_EXECUTABLE_FLAGS} pitdump
              COMMENT "Packing the executables"
              VERBATIM
          )
      endif ()
    endif ()
endif ()
