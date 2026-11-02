# Toolchain for cross-building the Linux gateway on a Debian host.
#
# The sysroot is assembled from target-architecture .deb files, because
# libwebsockets ships an architecture-specific lws_config.h and therefore cannot
# be co-installed with the host copy.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(FASTP2P_SYSROOT "/opt/arm64-sysroot" CACHE PATH "target sysroot")
set(CMAKE_SYSROOT "${FASTP2P_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH "${FASTP2P_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
