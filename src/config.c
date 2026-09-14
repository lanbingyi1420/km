#include "km_config.h"
#include "km_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define CONF_LINE_MAX  512
#define CONF_MAX_ITEMS 64

static const char *DEFAULT_CONF_PATH = "/etc/km/km.conf";

typedef struct {
    char key[64];
    char value[256];
} conf_item_t;

/* 去除字符串首尾空白（原地） */
static void trim_ws(char *s)
{
    char *p = s;
    char *end;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
}

/* 解析 INI 风格配置文件为 key=value 列表（忽略空行/注释/段标记）；文件不存在返回 -1 */
static int parse_conf_file(const char *path, conf_item_t *items, int max_items, int *count)
{
    FILE *fp;
    char line[CONF_LINE_MAX];
    int n = 0;

    fp = fopen(path, "r");
    if (fp == NULL)
        return -1; /* 文件不存在视为无文件配置 */

    while (fgets(line, sizeof(line), fp) != NULL && n < max_items) {
        char *eq;
        char *val;
        char key[64];

        trim_ws(line);
        if (line[0] == '\0' || line[0] == '#' || line[0] == '[')
            continue; /* 空行 / 注释 / 段标记 */

        eq = strchr(line, '=');
        if (eq == NULL)
            continue;

        *eq = '\0';
        val = eq + 1;
        trim_ws(line);
        trim_ws(val);

        /* 去掉行尾注释（value 中 # 后） */
        {
            char *c = strchr(val, '#');
            if (c) {
                *c = '\0';
                trim_ws(val);
            }
        }

        strncpy(key, line, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';
        if (key[0] == '\0')
            continue;

        strncpy(items[n].key, key, sizeof(items[n].key) - 1);
        items[n].key[sizeof(items[n].key) - 1] = '\0';
        strncpy(items[n].value, val, sizeof(items[n].value) - 1);
        items[n].value[sizeof(items[n].value) - 1] = '\0';
        n++;
    }
    fclose(fp);
    *count = n;
    return 0;
}

/* 在解析结果中按 key 查找值；未找到返回 NULL */
static const char *find_value(const conf_item_t *items, int count, const char *key)
{
    int i;
    for (i = 0; i < count; i++) {
        if (strcmp(items[i].key, key) == 0)
            return items[i].value;
    }
    return NULL;
}

/* 环境变量取值：KM_<KEY> 存在则优先，否则文件值，最后默认值 */
static const char *env_override(const char *key, const char *file_val, const char *def)
{
    char env_name[96];
    const char *ev;

    snprintf(env_name, sizeof(env_name), "KM_%s", key);
    for (unsigned i = 0; env_name[i]; i++)
        env_name[i] = (char)toupper((unsigned char)env_name[i]);

    ev = getenv(env_name);
    if (ev != NULL && ev[0] != '\0')
        return ev;
    if (file_val != NULL)
        return file_val;
    return def;
}

/* 加载配置：默认值 → 配置文件（路径优先级 显式 > KM_CONF > 默认）→ 环境变量覆盖 */
km_err_t km_config_load(km_config_t *cfg, const char *conf_path)
{
    conf_item_t items[CONF_MAX_ITEMS];
    int count = 0;
    const char *v;
    const char *path;

    if (cfg == NULL)
        return KM_ERR_BAD_PARAM;

    memset(cfg, 0, sizeof(*cfg));

    /* 默认值（按编译环境 KM_ENV 分别处理：通路 / GMAC 模式 / 目录） */
    cfg->heartbeat_interval = KM_DEFAULT_HEARTBEAT_SEC;
    cfg->selftest_enable = 1;
    cfg->selftest_interval = 3600;
    cfg->log_level = LOG_LEVEL_ERROR; /* 默认最高级：仅记录 error */
#if KM_ENV_IS_BOARD()
    /* 正式隔离架构环境：默认正式通路；GMAC 先沿用回环桩，接真实驱动后切 raw */
    cfg->comm_path = COMM_PATH_FORMAL;
    cfg->gmac_mode = GMAC_MODE_LOOPBACK;
    strncpy(cfg->oplog_dir, "/var/log/km/operational", sizeof(cfg->oplog_dir) - 1);
    strncpy(cfg->audit_dir, "/var/log/km/audit", sizeof(cfg->audit_dir) - 1);
    strncpy(cfg->key_dir, "/opt/km/keys", sizeof(cfg->key_dir) - 1);
    strncpy(cfg->cert_dir, "/opt/km/certs", sizeof(cfg->cert_dir) - 1);
#elif KM_ENV_IS_SIM_LINUX()
    /* Linux 单板联调：默认模拟通路（消息队列联调），系统目录 */
    cfg->comm_path = COMM_PATH_SIMULATION;
    cfg->gmac_mode = GMAC_MODE_LOOPBACK;
    strncpy(cfg->oplog_dir, "/var/log/km/operational", sizeof(cfg->oplog_dir) - 1);
    strncpy(cfg->audit_dir, "/var/log/km/audit", sizeof(cfg->audit_dir) - 1);
    strncpy(cfg->key_dir, "/opt/km/keys", sizeof(cfg->key_dir) - 1);
    strncpy(cfg->cert_dir, "/opt/km/certs", sizeof(cfg->cert_dir) - 1);
#else /* KM_ENV_SIM_WINDOWS：Windows 开发测试，默认模拟通路 + 本地相对目录 */
    cfg->comm_path = COMM_PATH_SIMULATION;
    cfg->gmac_mode = GMAC_MODE_LOOPBACK;
    strncpy(cfg->oplog_dir, "./logs/operational", sizeof(cfg->oplog_dir) - 1);
    strncpy(cfg->audit_dir, "./logs/audit", sizeof(cfg->audit_dir) - 1);
    strncpy(cfg->key_dir, "./data/keys", sizeof(cfg->key_dir) - 1);
    strncpy(cfg->cert_dir, "./data/certs", sizeof(cfg->cert_dir) - 1);
#endif
    cfg->provider = CRYPTO_PROVIDER_SOFT;
    strncpy(cfg->master_key_env, "KM_MASTER_KEY", sizeof(cfg->master_key_env) - 1);
    cfg->log_console = 1;  /* 默认开启后台打印 */
    cfg->log_to_file = 1;  /* 默认记录到文件 */
    cfg->log_file_max = 0;      /* 0=不限制 */
    cfg->log_file_count = 5;

    /* 配置文件路径：显式参数 > 环境变量 KM_CONF > 默认 */
    if (conf_path == NULL) {
        const char *cenv = getenv("KM_CONF");
        path = (cenv != NULL && cenv[0]) ? cenv : DEFAULT_CONF_PATH;
    } else {
        path = conf_path;
    }

    if (parse_conf_file(path, items, CONF_MAX_ITEMS, &count) == 0) {
        v = find_value(items, count, "heartbeat_interval");
        if (v != NULL) {
            int iv = atoi(v);
            if (iv > 0 && iv <= 86400)
                cfg->heartbeat_interval = iv;
        }
        v = find_value(items, count, "selftest_enable");
        if (v != NULL) {
            if (strcmp(v, "yes") == 0 || strcmp(v, "on") == 0 || strcmp(v, "1") == 0)
                cfg->selftest_enable = 1;
            else
                cfg->selftest_enable = 0;
        }
        v = find_value(items, count, "selftest_interval");
        if (v != NULL) {
            int iv = atoi(v);
            if (iv >= 0 && iv <= 86400)
                cfg->selftest_interval = iv;
        }
        v = find_value(items, count, "log_level");
        if (v != NULL) {
            if (strcmp(v, "debug") == 0) cfg->log_level = LOG_LEVEL_DEBUG;
            else if (strcmp(v, "warn") == 0) cfg->log_level = LOG_LEVEL_WARN;
            else if (strcmp(v, "error") == 0) cfg->log_level = LOG_LEVEL_ERROR;
            else cfg->log_level = LOG_LEVEL_INFO;
        }
        v = find_value(items, count, "oplog_dir");
        if (v != NULL) strncpy(cfg->oplog_dir, v, sizeof(cfg->oplog_dir) - 1);
        v = find_value(items, count, "audit_dir");
        if (v != NULL) strncpy(cfg->audit_dir, v, sizeof(cfg->audit_dir) - 1);
        v = find_value(items, count, "key_dir");
        if (v != NULL) strncpy(cfg->key_dir, v, sizeof(cfg->key_dir) - 1);
        v = find_value(items, count, "cert_dir");
        if (v != NULL) strncpy(cfg->cert_dir, v, sizeof(cfg->cert_dir) - 1);
        v = find_value(items, count, "provider");
        if (v != NULL) {
            if (strcmp(v, "pcie") == 0) cfg->provider = CRYPTO_PROVIDER_PCIE;
            else cfg->provider = CRYPTO_PROVIDER_SOFT;
        }
        v = find_value(items, count, "master_key_env");
        if (v != NULL) strncpy(cfg->master_key_env, v, sizeof(cfg->master_key_env) - 1);
        v = find_value(items, count, "gmac_mode");
        if (v != NULL) {
            if (strcmp(v, "raw") == 0) cfg->gmac_mode = GMAC_MODE_RAW;
            else cfg->gmac_mode = GMAC_MODE_LOOPBACK;
        }
        v = find_value(items, count, "comm_path");
        if (v != NULL) {
            if (strcmp(v, "simulation") == 0 || strcmp(v, "sim") == 0)
                cfg->comm_path = COMM_PATH_SIMULATION;
            else
                cfg->comm_path = COMM_PATH_FORMAL;
        }
        v = find_value(items, count, "log_console");
        if (v != NULL) {
            if (strcmp(v, "yes") == 0 || strcmp(v, "on") == 0 || strcmp(v, "1") == 0)
                cfg->log_console = 1;
            else
                cfg->log_console = 0;
        }
        v = find_value(items, count, "log_to_file");
        if (v != NULL) {
            if (strcmp(v, "yes") == 0 || strcmp(v, "on") == 0 || strcmp(v, "1") == 0)
                cfg->log_to_file = 1;
            else
                cfg->log_to_file = 0;
        }
        v = find_value(items, count, "log_file_max");
        if (v != NULL) {
            long lm = atol(v);
            if (lm >= 0) cfg->log_file_max = lm;
        }
        v = find_value(items, count, "log_file_count");
        if (v != NULL) {
            int fc = atoi(v);
            if (fc >= 1 && fc <= 100) cfg->log_file_count = fc;
        }
    }

    /* 环境变量覆盖（优先级最高） */
    v = env_override("OPLOG_DIR", NULL, NULL);
    if (v) strncpy(cfg->oplog_dir, v, sizeof(cfg->oplog_dir) - 1);
    v = env_override("AUDIT_DIR", NULL, NULL);
    if (v) strncpy(cfg->audit_dir, v, sizeof(cfg->audit_dir) - 1);
    v = env_override("KEY_DIR", NULL, NULL);
    if (v) strncpy(cfg->key_dir, v, sizeof(cfg->key_dir) - 1);
    v = env_override("CERT_DIR", NULL, NULL);
    if (v) strncpy(cfg->cert_dir, v, sizeof(cfg->cert_dir) - 1);
    v = env_override("HEARTBEAT_INTERVAL", NULL, NULL);
    if (v) {
        int iv = atoi(v);
        if (iv > 0 && iv <= 86400)
            cfg->heartbeat_interval = iv;
    }
    v = env_override("SELFTEST_ENABLE", NULL, NULL);
    if (v) {
        cfg->selftest_enable = (strcmp(v, "1") == 0 ||
                                strcmp(v, "yes") == 0 ||
                                strcmp(v, "on") == 0) ? 1 : 0;
    }
    v = env_override("SELFTEST_INTERVAL", NULL, NULL);
    if (v) {
        int iv = atoi(v);
        if (iv >= 0 && iv <= 86400)
            cfg->selftest_interval = iv;
    }
    v = env_override("COMM_PATH", NULL, NULL);
    if (v) {
        if (strcmp(v, "simulation") == 0 || strcmp(v, "sim") == 0)
            cfg->comm_path = COMM_PATH_SIMULATION;
        else
            cfg->comm_path = COMM_PATH_FORMAL;
    }
    v = env_override("LOG_CONSOLE", NULL, NULL);
    if (v) cfg->log_console = (strcmp(v, "1") == 0 || strcmp(v, "yes") == 0);
    v = env_override("LOG_TO_FILE", NULL, NULL);
    if (v) cfg->log_to_file = (strcmp(v, "1") != 0 && strcmp(v, "no") != 0);
    v = env_override("LOG_FILE_MAX", NULL, NULL);
    if (v) {
        long lm = atol(v);
        if (lm >= 0) cfg->log_file_max = lm;
    }
    v = env_override("LOG_FILE_COUNT", NULL, NULL);
    if (v) {
        int fc = atoi(v);
        if (fc >= 1 && fc <= 100) cfg->log_file_count = fc;
    }

    cfg->initialized = 1;
    return KM_ERR_OK;
}

/* 将已加载配置的关键项以 INFO 级写入运维日志 */
void km_config_dump(const km_config_t *cfg)
{
    if (cfg == NULL)
        return;
    km_oplog_write(LOG_LEVEL_INFO,
        "config heartbeat=%ds level=%d oplog=%s audit=%s key_dir=%s cert_dir=%s",
        cfg->heartbeat_interval, (int)cfg->log_level,
        cfg->oplog_dir, cfg->audit_dir, cfg->key_dir, cfg->cert_dir);
    km_oplog_write(LOG_LEVEL_INFO,
        "config provider=%s master_key_env=%s gmac=%s comm_path=%s "
        "log_console=%d log_to_file=%d log_file_max=%ld log_file_count=%d",
        cfg->provider == CRYPTO_PROVIDER_PCIE ? "pcie" : "soft",
        cfg->master_key_env,
        cfg->gmac_mode == GMAC_MODE_RAW ? "raw" : "loopback",
        cfg->comm_path == COMM_PATH_SIMULATION ? "simulation" : "formal",
        cfg->log_console, cfg->log_to_file, cfg->log_file_max, cfg->log_file_count);
    km_oplog_write(LOG_LEVEL_INFO,
        "config selftest_enable=%d selftest_interval=%ds",
        cfg->selftest_enable, cfg->selftest_interval);
}
