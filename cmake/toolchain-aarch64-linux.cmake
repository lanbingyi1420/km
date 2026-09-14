# E2000Q (ARM64) + Linux 交叉编译工具链配置（第二阶段启用）
#
# 用法：
#   cmake -S . -B out/km_board \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-aarch64-linux.cmake \
#       -DCMAKE_INSTALL_PREFIX=/opt/km
# 说明：需预装 aarch64-linux-gnu-gcc 交叉工具链；第一阶段本机开发不启用。

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_C_COMPILER_TARGET aarch64-linux-gnu)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a -mcpu=cortex-a53")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc")

set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
