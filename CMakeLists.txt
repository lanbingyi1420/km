cmake_minimum_required(VERSION 3.16)
project(km C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(MSVC)
    add_compile_options(/W4)
    # 源码为 UTF-8（含中文注释/字符串）：显式指定字符集，
    # 避免 MSVC 按系统代码页(936/GBK)误解析 UTF-8 字节导致注释泄漏/编译错误
    add_compile_options(/utf-8)
else()
    add_compile_options(-Wall -Wextra)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/cJSON)

# ============================================================
# 运行环境（编译期宏 KM_ENV）：BOARD / SIM_WINDOWS / SIM_LINUX
#   默认 SIM_WINDOWS（Windows 开发测试）；所有输出物统一收敛到 out/ 之下，
#   按平台分子目录（命名规则：下划线 + 平台标识）。切换示例：
#   cmake -S . -B out/km_board       -DKM_ENV=BOARD
#   cmake -S . -B out/km_sim_windows -DKM_ENV=SIM_WINDOWS
#   cmake -S . -B out/km_sim_linux   -DKM_ENV=SIM_LINUX
# ============================================================
set(KM_ENV "SIM_WINDOWS" CACHE STRING "Build environment: BOARD / SIM_WINDOWS / SIM_LINUX")
string(TOUPPER "${KM_ENV}" KM_ENV_UPPER)
if(KM_ENV_UPPER STREQUAL "BOARD")
    set(KM_ENV_DEF "KM_ENV_BOARD")
elseif(KM_ENV_UPPER STREQUAL "SIM_LINUX")
    set(KM_ENV_DEF "KM_ENV_SIM_LINUX")
elseif(KM_ENV_UPPER STREQUAL "SIM_WINDOWS")
    set(KM_ENV_DEF "KM_ENV_SIM_WINDOWS")
else()
    message(FATAL_ERROR "KM_ENV invalid: ${KM_ENV} (BOARD / SIM_WINDOWS / SIM_LINUX)")
endif()

# ============================================================
# 算法库：自研 SM2/SM3/SM4 纯软实现（零外部依赖）
# ============================================================
add_library(km_crypto STATIC
    src/hal/soft/sm2.c
    src/hal/soft/sm2_bignum.c
    src/hal/soft/sm2_rng.c
    src/hal/soft/sm3.c
    src/hal/soft/sm4.c
)
target_include_directories(km_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hal/soft
)
if(WIN32)
    # Windows 随机数源 BCryptGenRandom
    target_link_libraries(km_crypto PRIVATE bcrypt)
endif()

# ============================================================
# 核心业务库：HAL / 核心层 / 通信层 / 日志层 / 应用层
# ============================================================
add_library(km_core STATIC
    src/app/cmd_handler.c
    src/app/device_init.c
    src/app/heartbeat.c
    src/app/msg_dispatch.c
    src/comm/fpga_comm.c
    src/comm/gmac_comm.c
    src/comm/km_comm.c
    src/comm/mgmt_protocol.c
    src/comm/msg_queue.c
    src/config.c
    src/crc32.c
    src/core/cert_validator.c
    src/core/der.c
    src/env.c
    src/error.c
    src/core/crypto_engine.c
    src/core/key_manager.c
    src/hal/crypto_hal.c
    src/hal/pcie_crypto.c
    src/hal/soft_crypto.c
    third_party/cJSON/cJSON.c
    src/log/audit_log.c
    src/log/op_log.c
    src/thread.c
)
target_link_libraries(km_core PUBLIC km_crypto)
target_include_directories(km_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
# 多线程依赖（pthread）
if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(km_core PUBLIC Threads::Threads)
endif()
# 模拟通路（sim_comm）仅单板模拟环境编译，正式环境不携带模拟通道
if(NOT KM_ENV_UPPER STREQUAL "BOARD")
    target_sources(km_core PRIVATE src/comm/sim_comm.c)
endif()

# 传播环境宏 KM_ENV（km_core 与其链接方按同一环境编译）
target_compile_definitions(km_core PUBLIC KM_ENV=${KM_ENV_DEF})

# ============================================================
# 主程序：km
# ============================================================
add_executable(km src/main.c)
target_link_libraries(km PRIVATE km_core)

# ============================================================
# 演示工具：各级别日志内容模拟输出（km_log_demo）
# ============================================================
add_executable(km_log_demo tools/log_demo.c)
target_link_libraries(km_log_demo PRIVATE km_core)

# ============================================================
# 单元测试（CTest 驱动）
# ============================================================
enable_testing()

add_executable(km_tests
    tests/test_main.c
    tests/test_sm3.c
    tests/test_sm4.c
    tests/test_sm2.c
    tests/test_crypto_hal.c
    tests/test_log.c
    tests/test_selftest.c
    tests/test_cert_import.c
    tests/test_mgmt_protocol.c
    tests/test_comm_path.c
    tests/test_env.c
    tests/test_oplog.c
    tests/test_heartbeat.c
    tests/test_msg_dispatch.c
)
target_link_libraries(km_tests PRIVATE km_core)
add_test(NAME km_tests COMMAND km_tests)
# SIM_LINUX 单测跑在真实 System V 消息队列后端上（build.sh 注释早先声称的
# KM_MNG_MSGQ_FLUSH=1 预设此前未落地，此处兑现）：预设初始化即排空遗留帧，
# 并将测试工作目录固定为仓库根，保证队列状态与相对路径可控。
if(KM_ENV_UPPER STREQUAL "SIM_LINUX")
    set_tests_properties(km_tests PROPERTIES
        ENVIRONMENT "KM_MNG_MSGQ_FLUSH=1"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
