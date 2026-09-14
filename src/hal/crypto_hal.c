#include "crypto_hal.h"

/* SoftCryptoProvider / PcieCryptoProvider 的 HAL 接口表（由对应模块实现） */
extern const CryptoHAL km_soft_crypto_hal;
extern const CryptoHAL km_pcie_crypto_hal;

static const CryptoHAL *g_hal = NULL;

/* 初始化密码 HAL：按 provider 选择软实现或 PCIe 实现的接口表并调用其 init；失败返回 KM_ERR_INIT_FAIL */
km_err_t km_hal_init(crypto_provider_t provider, const void *cfg)
{
    const CryptoHAL *hal = NULL;
    int rc;

    if (provider == CRYPTO_PROVIDER_PCIE) {
        hal = &km_pcie_crypto_hal;
    } else {
        hal = &km_soft_crypto_hal;
    }
    if (hal == NULL || hal->init == NULL)
        return KM_ERR_INIT_FAIL;

    rc = hal->init(cfg);
    if (rc != 0)
        return KM_ERR_INIT_FAIL;

    g_hal = hal;
    return KM_ERR_OK;
}

/* 反初始化 HAL：调用当前实现的 deinit 并清空接口表 */
void km_hal_deinit(void)
{
    if (g_hal != NULL && g_hal->deinit != NULL)
        g_hal->deinit();
    g_hal = NULL;
}

/* 获取当前密码 HAL 接口表（未初始化时返回 NULL） */
const CryptoHAL *km_hal_get(void)
{
    return g_hal;
}
