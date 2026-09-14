# KM 项目 Code Review 报告（2026-09-14）

## 概述

- **Review 对象**：工作区相对提交 `434a225`（feat: 实现KM密钥管理软件第一阶段）的未提交改动，共 38 个文件，约 +2115/-418 行。
- **改动主题**：管理协议帧头改版（SMLT 9B → 统一 FPGA 帧头 8B，msg_cmd 扩 2B、新增 msg_id）、SIM_LINUX 真实 System V 消息队列联调后端、心跳上行载荷与运行状态上报、运维日志系统重构（级别重排 + 调用点定位 + DEBUG hex dump）、联调脚本（build.sh / sysmng_sim.c / msgq_probe.c）。
- **Review 方法**：通读全部 diff（3 个文件簇共 2736 行）+ 新增文件关键部分，对全部发现做了交叉核验（全库 grep、对照 `git show HEAD:` 旧实现）。
- **侧重点**：全面 —— 内存安全、并发、错误处理、协议安全、密码使用、可维护性、测试质量。
- **验证限制**：本机无 cmake/ninja（仅 MinGW gcc），未能复跑构建与单测；文中 Critical 结论均基于全库 grep 的确定性证据。

---

## Critical（必须修复）

### 1. `KM_MNG_MSGQ_KEY` 宏从未定义 → SIM_LINUX 编译直接失败

- 位置：`src/comm/sim_comm.c:50`（`#if KM_ENV_IS_SIM_LINUX()` 块内）
  ```c
  static key_t g_key = KM_MNG_MSGQ_KEY;
  ```
- 问题：全库搜索确认该宏没有任何 `#define`；`src/comm/sim_comm.h:34` 只定义了 `KM_MNG_MSGQ_KEY_DEFAULT`（=88）。SIM_WINDOWS 编译时该代码块被裁掉不受影响，Windows 单测全绿掩盖了它 —— 而 SIM_LINUX 正是本次联调改动的主战场。
- 修复：`KM_MNG_MSGQ_KEY` → `KM_MNG_MSGQ_KEY_DEFAULT`。

### 2. `getenv` 参数是错误粘贴的垃圾字符串，队列 key 覆盖彻底失效

- 位置：`src/comm/sim_comm.c:61`
  ```c
  env = getenv("crypto hal init failed: initialization failed");
  ```
- 问题：显然是从日志串误粘贴。该环境变量在任何环境下都不存在，key 恒为默认值 88。而 `scripts/build.sh:305,369` 导出的是 `KM_MSGQ_KEY`，`--msgq-key` 选项因此完全无效，非默认 key 的联调必然失败。
- 修复：`getenv("KM_MSGQ_KEY")`。

---

## Important（应当修复）

### 3. main.c 线程创建失败仅记日志照常运行，退出时对未初始化句柄 join

- 位置：`src/main.c:226-235`（创建）、`src/main.c:253-254`（退出 join）
- 问题：两处 `km_thread_create` 失败后只打日志继续：
  - 通信线程失败 → 主循环 `km_comm_frame_pop` 永远失败，进程"活着但失聪"；
  - 定时线程失败 → 无心跳、无定时自检；
  - 退出路径对未初始化的 `comm_t/timer_t` 调 `km_thread_join`（Windows 下对垃圾 HANDLE 等待，未定义行为）。
- 旧代码失败即 `return 1`，属于行为回退。
- 修复：任一线程创建失败即退出（或至少跳过对应 join 并记录降级状态）。

### 4. 心跳"问询 vs 迟到回执"的环形差值判别存在系统性误判窗口

- 位置：`src/app/heartbeat.c:226`
  ```c
  } else if ((uint8_t)(mh.msg_id - g_tx_msg_id) < 0x80u) {
  ```
- 问题：该启发式只在"问询 id − 最近主动 id ∈ (0,128)"窗口内成立。当 KM 主动 id 追上/超过对端问询 id 区段（`scripts/sysmng_sim.c:372` 用 `0x51+n` 高段；长跑后 KM id 回绕也会出现），合法问询被误判为"迟到回执"不予应答 → 对端误判 KM 离线。当前 hb 联调用例（interval=2s、q=3s）恰好在窗口内所以能过。
- 建议：协议层显式区分，不要靠 1 字节差值猜测 —— 如问询固定走高半段且 KM 主动 id 限低半段，或在 TLV 中加方向/类型标记。

### 5. `docs/api_spec.md:42` 仍是旧签名

- 文档写 `km_err_t km_device_init(const char *conf_path); // 七步启动链`，实际已是 `km_device_init(const km_config_t *cfg)` 五步链（`include/km_device.h:20`，配置加载与日志初始化移交 daemon main）。同文档其它部分均已同步，唯独此行漏改。

### 6. `cmake/km_version_copy.cmake` 是孤儿文件

- 文件注释自称"由 CMakeLists.txt 中 km 目标的 POST_BUILD 调用"，但 `CMakeLists.txt` 没有任何 `add_custom_command(POST_BUILD)` 引用它。要么接线，要么删除，避免误导。

---

## Minor（建议处理）

| # | 位置 | 问题 |
|---|------|------|
| 7 | `src/comm/sim_comm.c:7,15,52` | 注释中的环境变量名 `KM_MNG_MSGQ_KEY` 与 `sim_comm.h:24` / `km_env.h` / `build.sh` 的 `KM_MSGQ_KEY` 不一致，统一命名（配合 Critical #2） |
| 8 | `src/log/op_log.c` | `km_dbg_write_loc` / `km_dbg_hex_loc` 在级别过滤**之前**完成全部格式化（hex dump 最大 4096B），debug 关闭时热路径白付开销；建议入口先判 `g_inited && LOG_LEVEL_DEBUG >= g_level` |
| 9 | `src/comm/sim_comm.h` | `km_sim_poll_last` 的 SIM_LINUX 描述（"进程内回读即 msgrcv(mtype=1) 取走"）与实现（`MSG_COPY` 非破坏回读）不符 |
| 10 | `src/app/cmd_handler.c:13` | 注释仍写 TLV 偏移 17（应为 16） |
| 11 | `src/main.c` | 格式问题：`:215` `return 1;    }`、`:220` 逗号后无空格、`:251` `//exit deal` 注释；`:220` 线程数写死 `"3"` |
| 12 | `src/app/heartbeat.c:27` | `ensure_lock` 惰性初始化理论上有竞态（目前 main 先调 `km_heartbeat_init`，风险低，但 `km_heartbeat_set_run_state` 已暴露给任意线程调用） |
| 13 | `include/km_log.h` | `log_level_t` 枚举值重编号（INFO 0→1）：代码内均为符号引用无碍，若有外部按数值对接/持久化需注意 |
| 14 | `src/app/device_init.c` | 失败路径不回滚已初始化的 comm/hal（沿袭旧行为，建议后续补） |

---

## Strengths

- 协议改版干净：结构体即线格式 + `_Static_assert` 守住尺寸，文档（api_spec / km_env / 头文件注释）与代码同步率高，测试里的字节偏移断言全部跟着改。
- `heartbeat.c` 的 `g_pending_since` 修复了真 bug：原来以 `g_last_tx` 计时，周期重发不断刷新导致对端静默时永不判丢；注释把因果讲清楚了。
- sim_comm 双后端接口对上层稳定；EIDRM/EINVAL 自动重开、`KM_MNG_MSGQ_FLUSH` 预设经 CMake `set_tests_properties` 兑现，设计细心。
- `device_init` 改为接收调用方配置，消除了二次 `config_load/log_init2` 覆盖 `--conf` 的真实缺陷，注释说明了历史原因。
- 测试新增心跳载荷 TLV 往返、debug 级别过滤等真实行为校验。

---

## 总体结论

**With fixes（修复后可提交）。**

两个 Critical 都在 SIM_LINUX 路径上且互相叠加 —— 该路径当前**编译不过**；即使编译通过，key 覆盖也不生效。而 SIM_LINUX 联调正是本批改动（build.sh 的 smoke/hb、sysmng_sim / msgq_probe）的目的，必须在合并前修复，并至少在 Linux 上实际跑一次：

```bash
./scripts/build.sh all -p linux -e sim    # build + test + smoke
./scripts/build.sh hb  -p linux -e sim    # 双向心跳联调
```

Important #3（main.c 线程失败处理）建议一并修掉；其余为健壮性/一致性问题，可随后跟进。
