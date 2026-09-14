#!/usr/bin/env bash
# ============================================================
# KM 统一构建 / 测试 / 联调脚本（单一入口，win/linux 同一套）
#
# 两个正交维度（均显式指定，platform 可 auto 探测）映射到编译宏 KM_ENV：
#   -p platform  编译宿主机：win(MinGW gcc) / linux(本机 cc)
#   -e env       测试环境：  sim(模拟通路) / board(正式环境)
#
#   组合 -> KM_ENV：
#     linux + sim   -> SIM_LINUX    System V 消息队列联调后端（key 默认 88）
#     win   + sim   -> SIM_WINDOWS  内存 FIFO 队列（进程内注入/回读自测）
#     *     + board -> BOARD        正式通路裁剪（gmac loopback 桩，本机语法/逻辑验证）
#
#   构建输出统一收敛到 <ROOT>/out 之下，按平台分子目录（命名规则：下划线 + 平台标识）：
#     linux + sim   -> out/km_sim_linux
#     win   + sim   -> out/km_sim_windows
#     *     + board -> out/km_board
#   交叉编译（第二阶段，E2000Q/aarch64）：linux 宿主 + --toolchain
#   cmake/toolchain-aarch64-linux.cmake，env=board。
#
# 子命令（action）：
#   build  : 配置并编译 km / km_tests / km_core / km_crypto
#   test   : 运行 CTest（km_tests；SIM_LINUX 单测由 CMake 预设
#            KM_MNG_MSGQ_FLUSH=1 保证队列状态可控）
#   smoke  : 真实消息队列端到端冒烟（仅 linux+sim）：后台启动 km 主程序
#            （心跳经 --heartbeat 2 覆盖），msgq_probe 模拟"管理服务侧"
#            从 key 队列收 mtype=1 心跳帧
#   hb     : 与 sysmng 双向心跳联调（仅 linux+sim，见 scripts/sysmng_sim.c）：
#            A 回执+问询闭环，B 对照不回执验证 KM 超时告警
#   clean  : 删除构建目录；linux+sim 另清理遗留消息队列（ipcrm -Q key）
#   all    : build + test + （linux+sim 时追加 smoke）
#   help
#
# 用法：
#   ./scripts/build.sh <action> [-p|--platform auto|win|linux] \
#                        [-e|--env sim|board] [选项...]
# 选项：
#   -p|--platform <auto|win|linux>  编译宿主机（默认 auto 自动探测）
#   -e|--env <sim|board>            测试环境（默认 sim）
#   -t|--type <Debug|Release>       构建类型（默认 Debug，兼容 CMAKE_TYPE）
#   --dir <path>                    构建目录（默认 <ROOT>/out/km_<平台>，如 out/km_sim_windows）
#   --cc <compiler>                 编译器（默认 linux=cc / win=gcc）
#   --generator <name>              cmake 生成器（默认检测 ninja，否则平台默认）
#   --toolchain <file>              交叉工具链文件（如 cmake/toolchain-aarch64-linux.cmake）
#   --msgq-key <key>                System V 队列 key（默认 88，兼容 MSGQ_KEY）
#   -j|--jobs <n>                   并行度（默认 nproc）
#   -k|--keep                       保留 smoke/hb 临时现场（兼容 KEEP=1）
#   -h|--help
#
# 能力矩阵（不可用的 action 会明确提示并不执行）：
#   platform\env | sim               | board
#   linux        | build/test/smoke/hb | build/test
#   win          | build/test        | build/test
# win 平台请在 git-bash/msys bash 下运行本脚本。
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$(basename "$0")"

# ---- 参数（parse 后可覆盖） ----
ACTION="all"
PLATFORM_ARG="auto"
PLATFORM=""
ENV="sim"
TYPE="${CMAKE_TYPE:-Debug}"
BUILD_DIR_OPT=""
CC_OPT=""
GENERATOR_OPT=""
TOOLCHAIN=""
JOBS="${JOBS:-}"
KEEP="${KEEP:-0}"
MSGQ_KEY="${MSGQ_KEY:-88}"
# smoke/hb 现场清理（须为全局，EXIT trap 可读）
TMP=""
KM_PID=""

log() { printf '\033[1;34m[%s]\033[0m %s\n' "$SELF" "$*"; }
ok()  { printf '\033[1;32m[%s]\033[0m %s\n' "$SELF" "$*"; }
die() { printf '\033[1;31m[%s] FAIL: %s\033[0m\n' "$SELF" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
用法：./scripts/build.sh <action> [-p platform] [-e env] [选项]

  action: all|build|test|smoke|hb|clean|help   （默认 all）
  -p|--platform <auto|win|linux>  编译宿主机（默认 auto 自动探测）
  -e|--env <sim|board>            测试环境（默认 sim）
  -t|--type <Debug|Release>       构建类型
  --dir <path>                    构建目录（默认 <ROOT>/out/km_<平台>，如 out/km_sim_windows）
  --cc <compiler> / --generator <name> / --toolchain <file>
  --msgq-key <key> / -j|--jobs <n> / -k|--keep / -h|--help

能力矩阵（不可用 action 将提示并不执行）：
  platform\env | sim                 | board
  linux        | build/test/smoke/hb | build/test
  win          | build/test          | build/test

组合 -> 编译宏：linux+sim=SIM_LINUX  win+sim=SIM_WINDOWS  *+board=BOARD
win 平台请在 git-bash/msys bash 下运行。示例：
  ./scripts/build.sh build -p linux -e sim      # 当前开发环境
  ./scripts/build.sh all   -e sim               # linux+sim 全流程
  ./scripts/build.sh build -p win  -e board     # Windows 上编 board 版
EOF
}

# ---- 平台检测 / 映射 ----
detect_platform() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux*)      echo linux ;;
        MINGW*|MSYS*|CYGWIN*) echo win ;;
        *)           echo unsupported ;;
    esac
}

is_linux_sim() { [ "$PLATFORM" = "linux" ] && [ "$ENV" = "sim" ]; }

km_env_of() {
    # 输出编译宏 KM_ENV 值
    case "$ENV:$PLATFORM" in
        sim:linux)  echo SIM_LINUX ;;
        sim:win)    echo SIM_WINDOWS ;;
        board:*)    echo BOARD ;;
    esac
}

build_dir_of() {
    # 所有平台的输出物统一收敛到 <ROOT>/out 之下，按平台分子目录
    # （命名规则：下划线 + 平台标识）
    case "$ENV:$PLATFORM" in
        sim:linux)  echo "$ROOT/out/km_sim_linux" ;;
        sim:win)    echo "$ROOT/out/km_sim_windows" ;;
        board:*)    echo "$ROOT/out/km_board" ;;
    esac
}

# ---- 参数解析 ----
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)        ACTION="help"; return 0 ;;
            -p|--platform)
                [ $# -ge 2 ] || die "option $1 needs a value"
                PLATFORM_ARG="$2"; shift 2 ;;
            --platform=*)     PLATFORM_ARG="${1#*=}"; shift ;;
            -e|--env)
                [ $# -ge 2 ] || die "option $1 needs a value"
                ENV="$2"; shift 2 ;;
            --env=*)          ENV="${1#*=}"; shift ;;
            -t|--type)
                [ $# -ge 2 ] || die "option $1 needs a value"
                TYPE="$2"; shift 2 ;;
            --type=*)         TYPE="${1#*=}"; shift ;;
            --dir)
                [ $# -ge 2 ] || die "option $1 needs a value"
                BUILD_DIR_OPT="$2"; shift 2 ;;
            --dir=*)          BUILD_DIR_OPT="${1#*=}"; shift ;;
            --cc)
                [ $# -ge 2 ] || die "option $1 needs a value"
                CC_OPT="$2"; shift 2 ;;
            --cc=*)           CC_OPT="${1#*=}"; shift ;;
            --generator)
                [ $# -ge 2 ] || die "option $1 needs a value"
                GENERATOR_OPT="$2"; shift 2 ;;
            --generator=*)    GENERATOR_OPT="${1#*=}"; shift ;;
            --toolchain)
                [ $# -ge 2 ] || die "option $1 needs a value"
                TOOLCHAIN="$2"; shift 2 ;;
            --toolchain=*)    TOOLCHAIN="${1#*=}"; shift ;;
            --msgq-key)
                [ $# -ge 2 ] || die "option $1 needs a value"
                MSGQ_KEY="$2"; shift 2 ;;
            --msgq-key=*)     MSGQ_KEY="${1#*=}"; shift ;;
            -j|--jobs)
                [ $# -ge 2 ] || die "option $1 needs a value"
                JOBS="$2"; shift 2 ;;
            --jobs=*)         JOBS="${1#*=}"; shift ;;
            -k|--keep)        KEEP="1"; shift ;;
            *)                die "unknown option: $1 (see --help)" ;;
        esac
    done
}

resolve_vars() {
    case "$ACTION" in
        all|build|test|smoke|hb|clean|help) ;;
        *) die "unknown action: $ACTION (see --help)" ;;
    esac

    # 平台：auto 探测 -> 校验
    if [ "$PLATFORM_ARG" = "auto" ]; then
        PLATFORM="$(detect_platform)"
        if [ "$PLATFORM" = "unsupported" ]; then
            die "auto detect failed (uname=$(uname -s)); pass -p win|linux explicitly"
        fi
    else
        case "$PLATFORM_ARG" in
            win|linux) PLATFORM="$PLATFORM_ARG" ;;
            *) die "invalid --platform '$PLATFORM_ARG' (auto|win|linux)" ;;
        esac
    fi

    # 环境：校验
    case "$ENV" in
        sim|board) ;;
        *) die "invalid --env '$ENV' (sim|board)" ;;
    esac

    # 交叉工具链仅在 linux 宿主；文件须存在
    if [ -n "$TOOLCHAIN" ]; then
        [ "$PLATFORM" = "linux" ] || die "--toolchain (cross compile) only supported on linux host"
        [ -f "$TOOLCHAIN" ] || die "toolchain file not found: $TOOLCHAIN"
        TOOLCHAIN="$(cd "$(dirname "$TOOLCHAIN")" && pwd)/$(basename "$TOOLCHAIN")"
    fi

    if [ -z "$JOBS" ]; then
        JOBS="$(nproc 2>/dev/null || echo 4)"
    fi
    if [ -z "$BUILD_DIR_OPT" ]; then
        BUILD_DIR_OPT="$(build_dir_of)"
    fi
}

# ---- 平台相关准备：编译器 / cmake 生成器 ----
CC_FINAL=""
GEN=""
pick_cc_and_gen() {
    local cc_default
    cc_default="$([ "$PLATFORM" = "win" ] && echo gcc || echo cc)"
    if [ -n "$TOOLCHAIN" ]; then
        CC_FINAL=""          # 编译器由 toolchain 文件指定
    elif [ -n "$CC_OPT" ]; then
        CC_FINAL="$CC_OPT"
    elif [ -n "${CC:-}" ]; then
        CC_FINAL="$CC"
    else
        CC_FINAL="$cc_default"
    fi

    if [ -n "$GENERATOR_OPT" ]; then
        GEN="$GENERATOR_OPT"
    elif command -v ninja >/dev/null 2>&1; then
        GEN="Ninja"
    elif [ "$PLATFORM" = "win" ]; then
        GEN="MinGW Makefiles"
    else
        GEN="Unix Makefiles"
    fi
}

# 清理遗留消息队列（仅 linux+sim；不存在/无权限时忽略）
ipc_clean() {
    ipcrm -Q "$MSGQ_KEY" >/dev/null 2>&1 || true
}

# ---- actions ----
do_build() {
    log "configure -> $BUILD_DIR_OPT (KM_ENV=$KENV, platform=$PLATFORM, type=$TYPE, cc=${CC_FINAL:-toolchain})"
    local -a cfg=(
        cmake -S "$ROOT" -B "$BUILD_DIR_OPT"
        -DKM_ENV="$KENV" -DCMAKE_BUILD_TYPE="$TYPE"
    )
    [ -n "$GEN" ] && cfg+=(-G "$GEN")
    [ -n "$TOOLCHAIN" ] && cfg+=(-DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN")
    if [ -n "$CC_FINAL" ]; then
        CC="$CC_FINAL" "${cfg[@]}"
    else
        "${cfg[@]}"
    fi
    log "build -j$JOBS"
    cmake --build "$BUILD_DIR_OPT" -j "$JOBS"
    ok "build OK: $BUILD_DIR_OPT/km, $BUILD_DIR_OPT/km_tests"
}

do_test() {
    [ -x "$BUILD_DIR_OPT/km_tests" ] || die "km_tests not built, run 'build' first"
    log "ctest (km_tests; artifacts -> $ROOT/logs/tests)"
    # 测试进程 cwd 由 CMake WORKING_DIRECTORY 固定为仓库根；SIM_LINUX 的
    # KM_MNG_MSGQ_FLUSH=1 亦由 CMake 测试属性预设
    (cd "$BUILD_DIR_OPT" && ctest --output-on-failure)
    ok "ctest OK"
}

do_smoke() {
    is_linux_sim || die "smoke only supported on (platform=linux, env=sim)"
    [ -x "$BUILD_DIR_OPT/km" ] || die "km not built, run 'build' first"

    TMP="$(mktemp -d "${TMPDIR:-/tmp}/km_smoke.XXXXXX")"
    local PROBE="$TMP/msgq_probe"

    cleanup() {
        if [ -n "$KM_PID" ]; then kill "$KM_PID" >/dev/null 2>&1 || true; fi
        ipc_clean
        if [ "$KEEP" != "1" ]; then rm -rf "$TMP"; fi
    }
    trap cleanup EXIT

    log "compile probe: $ROOT/scripts/msgq_probe.c"
    "${CC_FINAL:-cc}" -Wall -Wextra -O2 "$ROOT/scripts/msgq_probe.c" -o "$PROBE" \
        || die "compile msgq_probe failed"

    ipc_clean
    export KM_MASTER_KEY="0123456789abcdef0123456789abcdef"
    # km 侧 sim_comm 经 KM_MSGQ_KEY 选取联调队列 key，须与对端 msgq_probe 一致
    export KM_MSGQ_KEY="$MSGQ_KEY"
    mkdir -p "$TMP/oplog" "$TMP/audit" "$TMP/keys" "$TMP/certs"
    cat > "$TMP/km.conf" <<EOF
heartbeat_interval=30
log_console=1
log_to_file=1
log_level=info
oplog_dir=$TMP/oplog
audit_dir=$TMP/audit
key_dir=$TMP/keys
cert_dir=$TMP/certs
selftest_enable=off
selftest_interval=3600
EOF

    log "start km daemon (conf=$TMP/km.conf + --heartbeat 2)"
    (cd "$ROOT" && exec "$BUILD_DIR_OPT/km" --conf "$TMP/km.conf" --heartbeat 2) \
        >"$TMP/km.out" 2>&1 &
    KM_PID=$!
    sleep 1

    if grep -q "config source: cli overrides: .*heartbeat_interval=2" "$TMP/km.out"; then
        ok "config ok: startup info logged 'cli overrides: heartbeat_interval=2'"
    else
        log "WARN: 'cli overrides' not found in km.out (check config source info logging)"
        tail -n 20 "$TMP/km.out" 2>/dev/null || true
    fi

    log "run msgq_probe: expect KM heartbeat frame (mtype=1) from key=$MSGQ_KEY"
    if "$PROBE" -k "$MSGQ_KEY" -w 8 -n 1; then
        ok "SMOKE OK: probe received KM report frame"
    else
        echo "---- km.out (tail) ----"
        tail -n 40 "$TMP/km.out" 2>/dev/null || true
        echo "---- ipcs -q ----"
        ipcs -q 2>/dev/null || true
        die "smoke failed; keep artifacts at: $TMP (rerun with -k)"
    fi
}

# 与 sysmng 双向心跳联调（sysmng_sim 模拟管理服务侧，System V 队列）：
#   stage A：回执 + 主动问询应答闭环，期间 km 不应判丢；
#   stage B：对照不回执，KM 按 interval*max_lost 判丢并告警。
do_hb() {
    is_linux_sim || die "hb only supported on (platform=linux, env=sim)"
    [ -x "$BUILD_DIR_OPT/km" ] || die "km not built, run 'build' first"

    TMP="$(mktemp -d "${TMPDIR:-/tmp}/km_hb.XXXXXX")"
    local SIM="$TMP/sysmng_sim"

    cleanup() {
        if [ -n "$KM_PID" ]; then kill "$KM_PID" >/dev/null 2>&1 || true; fi
        ipc_clean
        if [ "$KEEP" != "1" ]; then rm -rf "$TMP"; fi
    }
    trap cleanup EXIT

    log "compile sysmng_sim: $ROOT/scripts/sysmng_sim.c"
    "${CC_FINAL:-cc}" -Wall -Wextra -O2 "$ROOT/scripts/sysmng_sim.c" -o "$SIM" \
        || die "compile sysmng_sim failed"

    ipc_clean
    export KM_MASTER_KEY="0123456789abcdef0123456789abcdef"
    # km 侧 sim_comm 经 KM_MSGQ_KEY 选取联调队列 key，须与对端 sysmng_sim 一致
    export KM_MSGQ_KEY="$MSGQ_KEY"
    mkdir -p "$TMP/oplog" "$TMP/audit" "$TMP/keys" "$TMP/certs"
    cat > "$TMP/km.conf" <<EOF
heartbeat_interval=30
log_console=1
log_to_file=1
log_level=debug
oplog_dir=$TMP/oplog
audit_dir=$TMP/audit
key_dir=$TMP/keys
cert_dir=$TMP/certs
selftest_enable=off
selftest_interval=3600
EOF

    log "start km daemon (conf=$TMP/km.conf + --heartbeat 2)"
    (cd "$ROOT" && exec "$BUILD_DIR_OPT/km" --conf "$TMP/km.conf" --heartbeat 2) \
        >"$TMP/km.out" 2>&1 &
    KM_PID=$!
    sleep 2
    # 判定依据使用即时落盘的运维日志（控制台经重定向为块缓冲，不可作实时源）
    # 心跳联调：debug 级输出交互帧 hex（km_dbg_hex，每行 16B 含行号）
    local OPLOG="$TMP/oplog/oplog-$(date +%Y%m%d).log"
    local LOST_PAT="no reply within|link lost"
    [ -s "$OPLOG" ] || die "km oplog empty: $OPLOG (log not written?)"

    # ---- stage A：双向闭环（12s > 心跳超时窗 2s*3=6s） ----
    log "stage A: sysmng echo-reply + active query (expect no loss)"
    if "$SIM" -k "$MSGQ_KEY" -t 12 -q 3 -n 3 -v; then
        ok "stage A OK: sysmng_sim received KM heartbeats, echoes keep link alive, query answered"
    else
        echo "---- $OPLOG (tail) ----"
        tail -n 40 "$OPLOG" 2>/dev/null || true
        echo "---- ipcs -q ----"
        ipcs -q 2>/dev/null || true
        die "stage A failed; keep artifacts at: $TMP (rerun with -k)"
    fi
    if grep -qE "$LOST_PAT" "$OPLOG"; then
        echo "---- $OPLOG (tail) ----"
        tail -n 40 "$OPLOG" 2>/dev/null || true
        die "stage A failed: km logged heartbeat loss while sysmng replied"
    fi

    # ---- stage B：对照不回执 -> KM 判丢告警 ----
    log "stage B: sysmng silent - expect km heartbeat-loss warning"
    "$SIM" -k "$MSGQ_KEY" -E -q 0 -t 10 -n 1 >/dev/null 2>&1 || true
    sleep 8 # 最后一次心跳后 6s 判丢，留足日志落盘时间
    if grep -qE "$LOST_PAT" "$OPLOG"; then
        ok "stage B OK: km detected heartbeat loss after sysmng went silent"
    else
        echo "---- $OPLOG (tail) ----"
        tail -n 40 "$OPLOG" 2>/dev/null || true
        die "stage B failed: km did not log heartbeat loss after silence"
    fi

    echo "---- km daemon oplog (tail) ----"
    tail -n 15 "$OPLOG" 2>/dev/null || true
    ok "HB SMOKE OK: sysmng<->km heartbeat full-duplex verified"
}

do_clean() {
    log "remove build dir: $BUILD_DIR_OPT"
    rm -rf "$BUILD_DIR_OPT"
    # 平台子目录清空后，若 out 根目录已空则一并移除，避免残留空目录
    rmdir "$ROOT/out" 2>/dev/null || true
    if is_linux_sim; then ipc_clean; fi
    ok "clean OK"
}

# ---- main ----
ACTION="${1:-all}"
if [ $# -gt 0 ]; then shift; fi
parse_args "$@"
if [ "$ACTION" = "help" ]; then usage; exit 0; fi
resolve_vars
KENV="$(km_env_of)"

log "platform=$PLATFORM env=$ENV -> KM_ENV=$KENV, build dir=$BUILD_DIR_OPT"

case "$ACTION" in
    all)
        pick_cc_and_gen
        do_build
        do_test
        if is_linux_sim; then do_smoke; else
            log "skipped smoke: 仅 (linux, sim) 支持"
        fi
        ;;
    build)
        pick_cc_and_gen
        do_build
        ;;
    test)
        pick_cc_and_gen
        do_test
        ;;
    smoke)
        pick_cc_and_gen
        do_smoke
        ;;
    hb)
        pick_cc_and_gen
        do_hb
        ;;
    clean)
        do_clean
        ;;
esac
