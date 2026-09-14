/* ============================================================
 * SoftCryptoProvider：第一阶段纯软实现
 * 基于自研 SM2/SM3/SM4 算法库；密钥以加密文件形式存储于 key_dir。
 * 密钥容器格式：
 *   [magic:4B "KMKF"][version:1B][key_type:1B][key_id:32B]
 *   [iv:16B][ciphertext:96B][sm3_checksum:32B]  （总长 182B）
 * 明文 = SM2 私钥 32B || SM2 公钥 64B（SM4-CBC 加密）
 * 会话密钥 = SM3(master_key)[0:16]，主密钥经环境变量注入，不落盘。
 * ============================================================ */

#include "crypto_hal.h"
#include "sm2.h"
#include "sm2_rng.h"
#include "sm3.h"
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define KEY_FILE_MAGIC     "KMKF"
#define KEY_FILE_VERSION   1
#define KEY_PLAIN_LEN      (SM2_PRIKEY_LEN + SM2_PUBKEY_LEN) /* 96 */
#define KEY_FILE_LEN       (4 + 1 + 1 + 32 + SM4_BLOCK_LEN + KEY_PLAIN_LEN + 32)

#define DEFAULT_KEY_DIR    "/opt/km/keys"
#define DEFAULT_MASTER_ENV "KM_MASTER_KEY"

/* 全局状态 */
static char     g_key_dir[256];
static uint8_t  g_session_key[SM4_KEY_LEN]; /* SM3(master)[0:16] */
static int      g_session_key_valid = 0;

/* ---------- 平台辅助 ---------- */

/* 递归创建密钥目录（Windows: _mkdir / Linux: mkdir 0700） */
static void mkdir_p(const char *path)
{
#ifdef _WIN32
    _mkdir(path);
#else
    mkdir(path, 0700);
#endif
}

/* 收紧密钥文件权限为仅属主可读写（0600，Windows 忽略） */
static void set_file_perm(const char *path)
{
#ifdef _WIN32
    (void)path;
#else
    chmod(path, 0600);
#endif
}

/* 读取环境变量字符串到 out；未设置或为空返回 -1 */
static int read_env_str(const char *name, char *out, size_t cap)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return -1;
    strncpy(out, v, cap - 1);
    out[cap - 1] = '\0';
    return 0;
}

/* 派生会话密钥：SM3(master_key) 取前 16 字节 */
static void derive_session_key(const char *master_key)
{
    uint8_t digest[SM3_DIGEST_LEN];
    sm3_digest((const uint8_t *)master_key, strlen(master_key), digest);
    memcpy(g_session_key, digest, SM4_KEY_LEN);
    g_session_key_valid = 1;
}

/* 生成密钥标识：24 位随机十六进制（剩余 8 字节清零） */
static void gen_key_id(char out[KM_KEY_ID_LEN])
{
    static const char *hx = "0123456789abcdef";
    uint8_t rnd[12];
    int i;

    memset(out, 0, KM_KEY_ID_LEN);
    if (sm2_rng_bytes(rnd, sizeof(rnd)) != 0)
        memset(rnd, 0x5a, sizeof(rnd));

    for (i = 0; i < 12; i++) {
        out[i * 2]     = hx[rnd[i] >> 4];
        out[i * 2 + 1] = hx[rnd[i] & 0x0f];
    }
    out[24] = '\0';
}

/* 拼接密钥文件路径：key_dir/<key_id>.key */
static void key_file_path(const char *key_id, char *path, size_t cap)
{
    snprintf(path, cap, "%s/%s.key", g_key_dir, key_id);
}

/* ---------- 密钥文件存储 ---------- */

/* 将密钥对以 KMKF 容器加密落盘（SM4-CBC 密文 + SM3 校验）；成功返回 0 */
static int key_store_save(key_type_t type, const char *key_id,
                          const uint8_t prikey[SM2_PRIKEY_LEN],
                          const uint8_t pubkey[SM2_PUBKEY_LEN])
{
    uint8_t plain[KEY_PLAIN_LEN];
    uint8_t ct[KEY_PLAIN_LEN];
    uint8_t iv[SM4_BLOCK_LEN];
    uint8_t checksum[SM3_DIGEST_LEN];
    uint8_t file_buf[KEY_FILE_LEN];
    char path[512];
    FILE *fp;
    size_t off = 0;
    int rc = -1;

    if (!g_session_key_valid)
        return -1;

    memcpy(plain, prikey, SM2_PRIKEY_LEN);
    memcpy(plain + SM2_PRIKEY_LEN, pubkey, SM2_PUBKEY_LEN);

    if (sm2_rng_bytes(iv, sizeof(iv)) != 0)
        return -1;
    sm4_cbc_encrypt(g_session_key, iv, plain, ct, KEY_PLAIN_LEN);
    sm3_digest(plain, KEY_PLAIN_LEN, checksum);

    /* 组装容器 */
    memcpy(file_buf + off, KEY_FILE_MAGIC, 4); off += 4;
    file_buf[off++] = KEY_FILE_VERSION;
    file_buf[off++] = (uint8_t)type;
    memcpy(file_buf + off, key_id, 32); off += 32;
    memcpy(file_buf + off, iv, SM4_BLOCK_LEN); off += SM4_BLOCK_LEN;
    memcpy(file_buf + off, ct, KEY_PLAIN_LEN); off += KEY_PLAIN_LEN;
    memcpy(file_buf + off, checksum, SM3_DIGEST_LEN); off += SM3_DIGEST_LEN;

    key_file_path(key_id, path, sizeof(path));
    fp = fopen(path, "wb");
    if (fp == NULL)
        return -1;
    if (fwrite(file_buf, 1, KEY_FILE_LEN, fp) == KEY_FILE_LEN)
        rc = 0;
    fclose(fp);
    set_file_perm(path);
    return rc;
}

/* 从 KMKF 容器解密恢复密钥对（校验 magic/版本/类型/key_id 与 SM3 完整性）；成功返回 0 */
static int key_store_load(key_type_t type, const char *key_id,
                          uint8_t prikey[SM2_PRIKEY_LEN],
                          uint8_t pubkey[SM2_PUBKEY_LEN])
{
    uint8_t file_buf[KEY_FILE_LEN];
    uint8_t plain[KEY_PLAIN_LEN];
    uint8_t checksum[SM3_DIGEST_LEN];
    uint8_t calc[SM3_DIGEST_LEN];
    char path[512];
    FILE *fp;
    size_t off = 0;
    int rc = -1;

    if (!g_session_key_valid)
        return -1;

    key_file_path(key_id, path, sizeof(path));
    fp = fopen(path, "rb");
    if (fp == NULL)
        return -1;
    if (fread(file_buf, 1, KEY_FILE_LEN, fp) != KEY_FILE_LEN) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (memcmp(file_buf + off, KEY_FILE_MAGIC, 4) != 0)
        return -1;
    off += 4;
    if (file_buf[off++] != KEY_FILE_VERSION)
        return -1;
    if (file_buf[off++] != (uint8_t)type)
        return -1;
    /* key_id 字段校验 */
    if (strncmp((const char *)file_buf + off, key_id, 32) != 0)
        return -1;
    off += 32;

    {
        const uint8_t *iv = file_buf + off;
        off += SM4_BLOCK_LEN;
        const uint8_t *ct = file_buf + off;
        off += KEY_PLAIN_LEN;
        memcpy(checksum, file_buf + off, SM3_DIGEST_LEN);

        sm4_cbc_decrypt(g_session_key, iv, ct, plain, KEY_PLAIN_LEN);
        sm3_digest(plain, KEY_PLAIN_LEN, calc);
        if (memcmp(calc, checksum, SM3_DIGEST_LEN) != 0)
            return -1; /* 完整性校验失败 */

        memcpy(prikey, plain, SM2_PRIKEY_LEN);
        memcpy(pubkey, plain + SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);
        rc = 0;
    }
    return rc;
}

/* ---------- HAL 接口实现 ---------- */

/* Soft 实现初始化：读取密钥目录与主密钥环境变量，派生会话密钥并创建目录 */
static int soft_init(const void *cfg)
{
    const soft_crypto_cfg_t *sc = (const soft_crypto_cfg_t *)cfg;
    const char *key_dir = (sc != NULL && sc->key_dir != NULL) ? sc->key_dir : NULL;
    const char *env_name = (sc != NULL && sc->master_key_env != NULL)
                               ? sc->master_key_env : NULL;
    char master[128];

    if (key_dir == NULL)
        key_dir = DEFAULT_KEY_DIR;
    if (env_name == NULL)
        env_name = DEFAULT_MASTER_ENV;

    strncpy(g_key_dir, key_dir, sizeof(g_key_dir) - 1);
    g_key_dir[sizeof(g_key_dir) - 1] = '\0';

    if (read_env_str(env_name, master, sizeof(master)) != 0)
        return -1; /* 主密钥未注入 */
    derive_session_key(master);

    mkdir_p(g_key_dir);
    return 0;
}

/* Soft 实现反初始化：清空会话密钥并置无效 */
static void soft_deinit(void)
{
    g_session_key_valid = 0;
    memset(g_session_key, 0, sizeof(g_session_key));
}

/* Soft SM2 密钥对生成 */
static int soft_sm2_gen_keypair(uint8_t *pubkey, uint8_t *prikey)
{
    return sm2_gen_keypair(pubkey, prikey);
}

/* Soft SM2 签名 */
static int soft_sm2_sign(const uint8_t *prikey, const uint8_t *data,
                         size_t data_len, uint8_t *sig)
{
    return sm2_sign(prikey, data, data_len, sig);
}

/* Soft SM2 验签 */
static int soft_sm2_verify(const uint8_t *pubkey, const uint8_t *data,
                           size_t data_len, const uint8_t *sig)
{
    return sm2_verify(pubkey, data, data_len, sig);
}

/* Soft SM3 摘要 */
static int soft_sm3_digest(const uint8_t *in, size_t len,
                           uint8_t out[KM_SM3_DIGEST_LEN])
{
    sm3_digest(in, len, out);
    return 0;
}

/* Soft SM4-CBC 整段加密（len 须为 16 的倍数） */
static int soft_sm4_encrypt(const uint8_t key[KM_SM4_KEY_LEN],
                            const uint8_t iv[KM_SM4_BLOCK_LEN],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    if ((len & (SM4_BLOCK_LEN - 1)) != 0)
        return -1;
    sm4_cbc_encrypt(key, iv, in, out, len);
    return 0;
}

/* Soft SM4-CBC 整段解密（len 须为 16 的倍数） */
static int soft_sm4_decrypt(const uint8_t key[KM_SM4_KEY_LEN],
                            const uint8_t iv[KM_SM4_BLOCK_LEN],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    if ((len & (SM4_BLOCK_LEN - 1)) != 0)
        return -1;
    sm4_cbc_decrypt(key, iv, in, out, len);
    return 0;
}

/* 自检：SM2/SM3/SM4 已知答案测试 */
static int soft_self_test(void)
{
    /* SM3 KAT */
    {
        uint8_t d[32];
        static const uint8_t exp[32] = {
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
            0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
            0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
            0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
        };
        sm3_digest((const uint8_t *)"abc", 3, d);
        if (memcmp(d, exp, 32) != 0)
            return -1;
    }
    /* SM4 KAT */
    {
        static const uint8_t key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        };
        static const uint8_t pt[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        };
        static const uint8_t ct[16] = {
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
            0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
        };
        uint8_t out[16];
        sm4_cbc_encrypt(key, NULL, pt, out, 16);
        if (memcmp(out, ct, 16) != 0)
            return -1;
    }
    /* SM2 签名验签往返 */
    {
        uint8_t pub[SM2_PUBKEY_LEN], pri[SM2_PRIKEY_LEN], sig[SM2_SIG_LEN];
        const uint8_t msg[] = "self-test";
        if (sm2_gen_keypair(pub, pri) != 0)
            return -1;
        if (sm2_sign(pri, msg, sizeof(msg) - 1, sig) != 0)
            return -1;
        if (sm2_verify(pub, msg, sizeof(msg) - 1, sig) != 0)
            return -1;
    }
    return 0;
}

/* 密钥生命周期 */
/* 生成 SM2 密钥对并加密落盘，输出 24 位十六进制 key_id */
static int soft_key_gen_store(int key_type, char key_id[KM_KEY_ID_LEN])
{
    uint8_t pub[SM2_PUBKEY_LEN], pri[SM2_PRIKEY_LEN];

    if (key_type < KEY_TYPE_ROOT || key_type > KEY_TYPE_ENC)
        return -1;
    if (key_id == NULL)
        return -1;
    if (sm2_gen_keypair(pub, pri) != 0)
        return -1;

    gen_key_id(key_id);
    if (key_store_save((key_type_t)key_type, key_id, pri, pub) != 0)
        return -1;
    memset(pri, 0, sizeof(pri));
    return 0;
}

/* 从密钥文件加载指定类型与 ID 的密钥对（解密并校验完整性） */
static int soft_key_load(int key_type, const char *key_id,
                         uint8_t *prikey, uint8_t *pubkey)
{
    if (key_type < KEY_TYPE_ROOT || key_type > KEY_TYPE_ENC)
        return -1;
    if (key_id == NULL || prikey == NULL || pubkey == NULL)
        return -1;
    return key_store_load((key_type_t)key_type, key_id, prikey, pubkey);
}

/* 判断指定密钥文件是否存在且可正常解密加载；存在返回 1 */
static int soft_key_exists(int key_type, const char *key_id)
{
    uint8_t pri[SM2_PRIKEY_LEN], pub[SM2_PUBKEY_LEN];
    if (soft_key_load(key_type, key_id, pri, pub) != 0)
        return 0;
    return 1;
}

/* ---------- 密钥槽台账（key_index：签名=1 起步长 2；加密=签名+1） ----------
 * 台账持久化于 key_dir/slot.ledger，每行：<key_id> <key_type> <key_index>
 * 用于设备证书导入时的公钥匹配（Q1/B/C 决策）。 */

#define SLOT_MAX 64

static char g_slot_ids[SLOT_MAX][KM_KEY_ID_LEN];
static int  g_slot_types[SLOT_MAX];
static int  g_slot_indexes[SLOT_MAX];
static int  g_slot_count = 0;
static int  g_slot_loaded = 0;

/* 拼接台账文件路径 */
static void slot_ledger_path(char *path, size_t cap)
{
    snprintf(path, cap, "%s/slot.ledger", g_key_dir);
}

/* 从磁盘加载台账；无文件视为空台账 */
static void slot_ledger_load(void)
{
    char path[512];
    FILE *fp;
    char line[160];

    g_slot_count = 0;
    slot_ledger_path(path, sizeof(path));
    fp = fopen(path, "r");
    if (fp == NULL) {
        g_slot_loaded = 1;
        return;
    }
    while (g_slot_count < SLOT_MAX && fgets(line, sizeof(line), fp) != NULL) {
        char id[KM_KEY_ID_LEN] = {0};
        int type = 0, idx = 0;
        if (sscanf(line, "%31s %d %d", id, &type, &idx) == 3) {
            strncpy(g_slot_ids[g_slot_count], id, KM_KEY_ID_LEN - 1);
            g_slot_ids[g_slot_count][KM_KEY_ID_LEN - 1] = '\0';
            g_slot_types[g_slot_count] = type;
            g_slot_indexes[g_slot_count] = idx;
            g_slot_count++;
        }
    }
    fclose(fp);
    g_slot_loaded = 1;
}

/* 将台账写回磁盘；失败返回 -1 */
static int slot_ledger_save(void)
{
    char path[512];
    FILE *fp;
    int i;

    slot_ledger_path(path, sizeof(path));
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    for (i = 0; i < g_slot_count; i++)
        fprintf(fp, "%s %d %d\n", g_slot_ids[i], g_slot_types[i], g_slot_indexes[i]);
    fclose(fp);
    return 0;
}

/* 生成密钥并分配槽位：签名 1,3,5,…；加密 2,4,6,…（=签名+1）
 * 该类型无现有槽位时从基础值起步（签名 1 / 加密 2）。 */
static int slot_alloc_index(int key_type)
{
    int base = (key_type == KEY_TYPE_SIGN) ? 1 : 2;
    int max = 0;
    int i;

    for (i = 0; i < g_slot_count; i++) {
        if (g_slot_types[i] == key_type && g_slot_indexes[i] > max)
            max = g_slot_indexes[i];
    }
    return (max == 0) ? base : max + 2;
}

static int soft_slot_gen_store(int key_type, char key_id[KM_KEY_ID_LEN],
                               int *key_index)
{
    uint8_t pub[SM2_PUBKEY_LEN], pri[SM2_PRIKEY_LEN];
    int idx;

    if (key_type != KEY_TYPE_SIGN && key_type != KEY_TYPE_ENC)
        return -1;
    if (key_id == NULL || key_index == NULL)
        return -1;
    if (!g_slot_loaded)
        slot_ledger_load();
    if (g_slot_count >= SLOT_MAX)
        return -1;
    if (sm2_gen_keypair(pub, pri) != 0)
        return -1;

    gen_key_id(key_id);
    if (key_store_save((key_type_t)key_type, key_id, pri, pub) != 0) {
        memset(pri, 0, sizeof(pri));
        return -1;
    }
    memset(pri, 0, sizeof(pri));

    idx = slot_alloc_index(key_type);
    strncpy(g_slot_ids[g_slot_count], key_id, KM_KEY_ID_LEN - 1);
    g_slot_ids[g_slot_count][KM_KEY_ID_LEN - 1] = '\0';
    g_slot_types[g_slot_count] = key_type;
    g_slot_indexes[g_slot_count] = idx;
    g_slot_count++;
    if (slot_ledger_save() != 0)
        return -1;

    *key_index = idx;
    return 0;
}

/* 按公钥在指定类型槽位中匹配，返回 key_index；未匹配返回 -1 */
static int soft_slot_find_pubkey(int key_type, const uint8_t *pubkey)
{
    uint8_t pri[SM2_PRIKEY_LEN], pub[SM2_PUBKEY_LEN];
    int i;

    if (pubkey == NULL)
        return -1;
    if (!g_slot_loaded)
        slot_ledger_load();
    for (i = 0; i < g_slot_count; i++) {
        if (g_slot_types[i] != key_type)
            continue;
        if (key_store_load((key_type_t)key_type, g_slot_ids[i], pri, pub) == 0) {
            if (memcmp(pub, pubkey, SM2_PUBKEY_LEN) == 0)
                return g_slot_indexes[i];
        }
    }
    return -1;
}

const CryptoHAL km_soft_crypto_hal = {
    .init            = soft_init,
    .deinit          = soft_deinit,
    .sm2_gen_keypair = soft_sm2_gen_keypair,
    .sm2_sign        = soft_sm2_sign,
    .sm2_verify      = soft_sm2_verify,
    .sm3_digest      = soft_sm3_digest,
    .sm4_encrypt     = soft_sm4_encrypt,
    .sm4_decrypt     = soft_sm4_decrypt,
    .self_test       = soft_self_test,
    .key_gen_store   = soft_key_gen_store,
    .key_load        = soft_key_load,
    .key_exists      = soft_key_exists,
    .slot_gen_store  = soft_slot_gen_store,
    .slot_find_pubkey = soft_slot_find_pubkey,
};
