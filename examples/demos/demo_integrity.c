/**
 * demo_integrity.c — 完整性保护演示（HMAC-SM3）
 *
 * 场景：发送方对一段数据计算 HMAC-SM3，接收方用相同密钥重新计算并对比，
 *       若一致则证明数据未被篡改。
 *
 * 编译：见同目录 Makefile，执行 make demo_integrity
 * 运行：./demo_integrity
 *
 * 前提：可执行文件同目录下需有 config.toml（日志配置）
 */

#include <stdio.h>
#include <string.h>
#include "sdf.h"

/* ──────────────── 辅助：打印十六进制 ──────────────── */
static void print_hex(const char *label, const unsigned char *data, unsigned int len)
{
    printf("  %-12s: ", label);
    for (unsigned int i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n               ");
    }
    printf("\n");
}

/* ──────────────── 辅助：检查返回值，失败则打印并跳转 ──────────────── */
#define CHECK(call, label) \
    do { \
        int _rv = (call); \
        if (_rv != SDR_OK) { \
            printf("[ERROR] %s 失败，错误码 0x%08X\n", (label), _rv); \
            goto cleanup; \
        } \
        printf("[OK]    %s\n", (label)); \
    } while (0)

/* ────────────────────────────────────────────────────
 * 计算 HMAC-SM3
 *
 * 参数：
 *   session  — 已打开的会话句柄
 *   key      — 明文密钥字节（16 字节）
 *   data     — 待保护的数据
 *   data_len — 数据长度
 *   hmac_out — 输出缓冲区（至少 32 字节）
 *
 * 步骤：
 *   1. ImportKey   — 把明文密钥导入设备，得到句柄
 *   2. HMACInit    — 告诉设备"我要用这个密钥算 HMAC-SM3"
 *   3. HMACUpdate  — 把数据喂进去（大文件可以分块多次调用）
 *   4. HMACFinal   — 拿到最终的 32 字节 HMAC 值
 *   5. DestroyKey  — 释放密钥句柄（必须，避免句柄泄漏）
 * ──────────────────────────────────────────────────── */
static int compute_hmac(void *session,
                        const unsigned char *key, unsigned int key_len,
                        const unsigned char *data, unsigned int data_len,
                        unsigned char *hmac_out, unsigned int *hmac_len)
{
    void *hKey = NULL;
    int rv;

    /* 步骤 1：导入明文密钥 */
    rv = SDF_ImportKey(session, key, key_len, &hKey);
    if (rv != SDR_OK) return rv;

    /* 步骤 2：初始化 HMAC-SM3 */
    rv = SDF_HMACInit(session, hKey, SGD_SM3);
    if (rv != SDR_OK) { SDF_DestroyKey(session, hKey); return rv; }

    /* 步骤 3：输入数据（本例一次性输入，大文件可分块） */
    rv = SDF_HMACUpdate(session, data, data_len);
    if (rv != SDR_OK) { SDF_DestroyKey(session, hKey); return rv; }

    /* 步骤 4：得到 32 字节 HMAC 值 */
    rv = SDF_HMACFinal(session, hmac_out, hmac_len);

    /* 步骤 5：无论成功与否，都要释放密钥句柄 */
    SDF_DestroyKey(session, hKey);
    return rv;
}

/* ──────────────────────────────────────────────────── */

int main(void)
{
    printf("========================================\n");
    printf("  完整性保护演示：HMAC-SM3\n");
    printf("========================================\n\n");

    void *hDevice  = NULL;
    void *hSession = NULL;
    int   rv       = SDR_OK;

    /* ── 打开设备和会话 ── */
    CHECK(SDF_OpenDevice(&hDevice),              "SDF_OpenDevice");
    CHECK(SDF_OpenSession(hDevice, &hSession),   "SDF_OpenSession");

    /* ── 测试数据 ── */

    /* 通信双方事先约定的共享密钥（实际场景通过安全信道分发） */
    unsigned char shared_key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /* 待保护的消息（模拟一条支付指令） */
    const char *message = "transfer:account=6225881234567890,amount=1000.00,currency=CNY";
    unsigned int msg_len = (unsigned int)strlen(message);

    printf("【发送方】\n");
    printf("  原始消息 : %s\n", message);
    print_hex("密钥", shared_key, sizeof(shared_key));

    /* ── 发送方：计算 HMAC ── */
    unsigned char hmac_sender[32] = {0};
    unsigned int  hmac_len = 0;

    rv = compute_hmac(hSession,
                      shared_key, sizeof(shared_key),
                      (const unsigned char *)message, msg_len,
                      hmac_sender, &hmac_len);
    if (rv != SDR_OK) {
        printf("[ERROR] 计算 HMAC 失败，错误码 0x%08X\n", rv);
        goto cleanup;
    }
    printf("[OK]    计算 HMAC-SM3\n");
    print_hex("HMAC 值", hmac_sender, hmac_len);

    printf("\n【接收方】\n");

    /* ── 接收方：用相同密钥重新计算 HMAC，然后对比 ── */
    /*
     * 实际场景：接收方收到 (message, hmac_sender)，
     * 用事先约定的同一把密钥重新算 HMAC，
     * 如果结果与收到的 HMAC 一致，则消息未被篡改。
     */
    unsigned char hmac_receiver[32] = {0};
    unsigned int  hmac_len2 = 0;

    rv = compute_hmac(hSession,
                      shared_key, sizeof(shared_key),
                      (const unsigned char *)message, msg_len,
                      hmac_receiver, &hmac_len2);
    if (rv != SDR_OK) {
        printf("[ERROR] 验证 HMAC 失败，错误码 0x%08X\n", rv);
        goto cleanup;
    }
    printf("[OK]    重新计算 HMAC-SM3\n");
    print_hex("HMAC 值", hmac_receiver, hmac_len2);

    /* ── 对比两个 HMAC 值 ── */
    printf("\n【验证结果】\n");
    if (hmac_len == hmac_len2 && memcmp(hmac_sender, hmac_receiver, hmac_len) == 0) {
        printf("  ✓ HMAC 一致，消息完整性验证通过！\n");
    } else {
        printf("  ✗ HMAC 不一致，消息可能已被篡改！\n");
        rv = SDR_VERIFYERR;
    }

    /* ── 模拟篡改场景 ── */
    printf("\n【模拟篡改】\n");
    const char *tampered = "transfer:account=6225881234567890,amount=9999.99,currency=CNY";
    printf("  篡改消息 : %s\n", tampered);

    unsigned char hmac_tampered[32] = {0};
    unsigned int  hmac_len3 = 0;

    compute_hmac(hSession,
                 shared_key, sizeof(shared_key),
                 (const unsigned char *)tampered, (unsigned int)strlen(tampered),
                 hmac_tampered, &hmac_len3);

    if (memcmp(hmac_sender, hmac_tampered, hmac_len) != 0) {
        printf("  ✓ HMAC 不一致，篡改行为被成功检测！\n");
    }

cleanup:
    if (hSession) SDF_CloseSession(hSession);
    if (hDevice)  SDF_CloseDevice(hDevice);

    printf("\n演示结束。\n");
    return (rv == SDR_OK) ? 0 : 1;
}
