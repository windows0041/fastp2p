# Toolchain for fully static musl Linux cross builds.
#
# The dependency script passes the compiler, archiver and target name explicitly,
# so one file serves every architecture.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR "${FASTP2P_TARGET_ARCH}")
set(CMAKE_C_COMPILER "${CMAKE_C_COMPILER}" CACHE FILEPATH "musl cross compiler")
set(CMAKE_AR "${CMAKE_AR}" CACHE FILEPATH "archiver")
set(CMAKE_RANLIB "${CMAKE_RANLIB}" CACHE FILEPATH "ranlib")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-static")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
