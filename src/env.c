/* 运行环境支持：环境名称 / 描述（编译期宏 KM_ENV 决定，见 km_env.h） */

#include "km_env.h"

const char *km_env_name(void)
{
#if KM_ENV_IS_BOARD()
    return "board";
#elif KM_ENV_IS_SIM_LINUX()
    return "sim_linux";
#else
    return "sim_windows";
#endif
}

const char *km_env_desc(void)
{
#if KM_ENV_IS_BOARD()
    return "formal isolated architecture: formal path (MgmtProtocol + GMAC + FPGA), formal fpga header";
#elif KM_ENV_IS_SIM_LINUX()
    return "single-board simulation on Linux: sim path (System V msg queue, key default 88), unified fpga header";
#else
    return "single-board simulation on Windows: sim path (in-memory message queue), unified fpga header";
#endif
}
