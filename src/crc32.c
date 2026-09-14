#include "comm/mgmt_protocol.h"

/* CRC32（zlib 多项式 0xEDB88320，初始 0xFFFFFFFF，输出异或 0xFFFFFFFF） */
static uint32_t g_crc_table_ready = 0;
static uint32_t g_crc_table[256];

/* 惰性初始化 CRC32 查表（zlib 多项式 0xEDB88320） */
static void crc_table_init(void)
{
    uint32_t i, j;
    for (i = 0; i < 256; i++) {
        uint32_t c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
    g_crc_table_ready = 1;
}

/* 增量计算 CRC32（调用方以 KM_CRC32_INIT 起始）；返回当前校验值 */
uint32_t km_crc32(uint32_t crc, const uint8_t *data, size_t len)
{
    size_t i;

    if (!g_crc_table_ready)
        crc_table_init();

    for (i = 0; i < len; i++)
        crc = g_crc_table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc;
}
