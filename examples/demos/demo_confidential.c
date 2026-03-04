/**
 * demo_confidential.c — 机密性保护演示（SM4-CBC 加解密）
 *
 * 场景：发送方用 SM4-CBC 加密敏感报文，接收方用相同密钥解密还原原文。
 *       演示随机 IV 生成、明文填充（PKCS#7）、加解密全流程。
 *
 * 编译：见同目录 Makefile，执行 make demo_confidential
 * 运行：./demo_confidential
 *
 * 前提：可执行文件同目录下需有 config.toml（日志配置）
 */

#include <stdio.h>
#include <string.h>
#include "sdf.h"

/* SM4 块大小固定 16 字节 */
#define SM4_BLOCK_SIZE 16

/* ──────────────── 辅助：打印十六进制 ──────────────── */
static void print_hex(const char *label, const unsigned char *data, unsigned int len)
{
    printf("  %-14s: ", label);
    for (unsigned int i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n                  ");
    }
    printf("\n");
}

/* ──────────────── PKCS#7 填充 ────────────────
 * SM4-CBC 要求明文长度是 16 的倍数。
 * PKCS#7 规则：在末尾追加 N 个值为 N 的字节，N = 16 - (len % 16)。
 * 若明文已经对齐，仍追加一整块（16 字节）0x10，方便解填充时判断。
 *
 * padded_out 由调用者分配，大小至少 len + 16。
 * ──────────────────────────────────────────── */
static unsigned int pkcs7_pad(const unsigned char *in, unsigned int len,
                               unsigned char *padded_out)
{
    unsigned int pad = SM4_BLOCK_SIZE - (len % SM4_BLOCK_SIZE);
    memcpy(padded_out, in, len);
    memset(padded_out + len, (int)pad, pad);
    return len + pad;
}

/* ──────────────── PKCS#7 去填充 ────────────────
 * 返回原始数据长度；若填充非法返回 0。
 * ──────────────────────────────────────────── */
static unsigned int pkcs7_unpad(const unsigned char *in, unsigned int len,
                                 unsigned char *out)
{
    if (len == 0 || len % SM4_BLOCK_SIZE != 0) return 0;
    unsigned char pad = in[len - 1];
    if (pad == 0 || pad > SM4_BLOCK_SIZE) return 0;
    /* 校验所有填充字节 */
    for (unsigned int i = len - pad; i < len; i++) {
        if (in[i] != pad) return 0;
    }
    unsigned int plain_len = len - pad;
    memcpy(out, in, plain_len);
    return plain_len;
}

/* ──────────────────────────────────────────── */

int main(void)
{
    printf("========================================\n");
    printf("  机密性保护演示：SM4-CBC 加解密\n");
    printf("========================================\n\n");

    void *hDevice  = NULL;
    void *hSession = NULL;
    int   rv       = SDR_OK;

    /* 缓冲区 */
    unsigned char padded[256]    = {0};   /* 填充后的明文 */
    unsigned char ciphertext[256] = {0};  /* 密文 */
    unsigned char decrypted[256] = {0};   /* 解密后数据 */
    unsigned char plaintext[256] = {0};   /* 去填充后原文 */
    unsigned int  ct_len  = 0;
    unsigned int  dec_len = 0;

    /* ── 打开设备和会话 ── */
    rv = SDF_OpenDevice(&hDevice);
    if (rv != SDR_OK) { printf("[ERROR] SDF_OpenDevice 失败 0x%08X\n", rv); return 1; }
    rv = SDF_OpenSession(hDevice, &hSession);
    if (rv != SDR_OK) { printf("[ERROR] SDF_OpenSession 失败 0x%08X\n", rv);
                        SDF_CloseDevice(hDevice); return 1; }
    printf("[OK]    打开设备和会话\n\n");

    /* ── 准备测试数据 ── */

    /*
     * 对称密钥：通信双方事先通过安全信道共享。
     * 实际场景可用 SDF_GenerateKeyWithKEK 由设备随机生成，
     * 这里为方便演示直接写死。
     */
    unsigned char sym_key[16] = {
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA
    };

    /*
     * IV（初始化向量）：每次加密必须随机生成，绝不能复用同一个 IV。
     * 复用 IV 会让攻击者能够分析密文的模式，破坏机密性。
     * 这里用 SDF_GenerateRandom 生成，模拟正确做法。
     */
    unsigned char iv[16] = {0};
    rv = SDF_GenerateRandom(hSession, sizeof(iv), iv);
    if (rv != SDR_OK) { printf("[ERROR] 生成随机 IV 失败 0x%08X\n", rv); goto cleanup; }
    printf("[OK]    生成随机 IV\n");

    /* 模拟需要加密的敏感报文 */
    const char *secret = "【机密】用户身份证号：110101199003070012，银行卡：6225881234567890";
    unsigned int secret_len = (unsigned int)strlen(secret);

    printf("\n【发送方】\n");
    printf("  原始明文 : %s\n", secret);
    printf("  明文长度 : %u 字节\n", secret_len);
    print_hex("IV", iv, sizeof(iv));
    print_hex("密钥", sym_key, sizeof(sym_key));

    /* ── 步骤 1：明文填充到 16 字节对齐 ── */
    unsigned int padded_len = pkcs7_pad((const unsigned char *)secret, secret_len, padded);
    printf("\n  填充后长度: %u 字节（补 %u 字节使之对齐到 SM4 块大小 16）\n",
           padded_len, padded_len - secret_len);

    /* ── 步骤 2：导入密钥 ── */
    void *hKey_enc = NULL;
    rv = SDF_ImportKey(hSession, sym_key, sizeof(sym_key), &hKey_enc);
    if (rv != SDR_OK) { printf("[ERROR] 导入加密密钥失败 0x%08X\n", rv); goto cleanup; }
    printf("[OK]    导入对称密钥（发送方）\n");

    /* ── 步骤 3：SM4-CBC 加密 ── */
    /*
     * 注意：IV 会在加密过程中被 SM4 内部修改（CBC 链式操作）。
     * 解密时必须使用与加密开始时相同的 IV，所以需要将 IV 随密文一起传给接收方。
     * 这里保存一份加密前的 IV 副本用于后续对比展示。
     */
    unsigned char iv_for_enc[16];
    memcpy(iv_for_enc, iv, sizeof(iv));

    ct_len = sizeof(ciphertext);
    rv = SDF_Encrypt(hSession, hKey_enc, SGD_SM4_CBC, iv_for_enc,
                     padded, padded_len, ciphertext, &ct_len);
    if (rv != SDR_OK) { printf("[ERROR] SM4-CBC 加密失败 0x%08X\n", rv);
                        SDF_DestroyKey(hSession, hKey_enc); goto cleanup; }
    printf("[OK]    SM4-CBC 加密完成\n");
    print_hex("密文", ciphertext, ct_len);
    printf("  密文长度 : %u 字节\n", ct_len);

    SDF_DestroyKey(hSession, hKey_enc);  /* 发送方用完密钥句柄立即释放 */

    /* ── 步骤 4：接收方导入相同密钥 ── */
    printf("\n【接收方】\n");
    void *hKey_dec = NULL;
    rv = SDF_ImportKey(hSession, sym_key, sizeof(sym_key), &hKey_dec);
    if (rv != SDR_OK) { printf("[ERROR] 导入解密密钥失败 0x%08X\n", rv); goto cleanup; }
    printf("[OK]    导入对称密钥（接收方）\n");

    /* ── 步骤 5：SM4-CBC 解密 ── */
    /*
     * 解密时 IV 必须与加密时相同。
     * 实际传输时 IV 通常附在密文头部明文传输（IV 本身不需要保密，但不能被篡改）。
     */
    dec_len = sizeof(decrypted);
    rv = SDF_Decrypt(hSession, hKey_dec, SGD_SM4_CBC, iv,  /* iv 是最初生成的随机 IV */
                     ciphertext, ct_len, decrypted, &dec_len);
    if (rv != SDR_OK) { printf("[ERROR] SM4-CBC 解密失败 0x%08X\n", rv);
                        SDF_DestroyKey(hSession, hKey_dec); goto cleanup; }
    printf("[OK]    SM4-CBC 解密完成\n");

    SDF_DestroyKey(hSession, hKey_dec);

    /* ── 步骤 6：去掉 PKCS#7 填充，还原原始明文 ── */
    unsigned int plain_len = pkcs7_unpad(decrypted, dec_len, plaintext);
    if (plain_len == 0) {
        printf("[ERROR] 去填充失败，数据可能损坏\n");
        rv = SDR_UNKNOWERR;
        goto cleanup;
    }
    plaintext[plain_len] = '\0';  /* 补 NULL 终止符，方便当字符串打印 */

    printf("\n【验证结果】\n");
    printf("  还原明文 : %s\n", plaintext);
    printf("  明文长度 : %u 字节\n", plain_len);

    if (plain_len == secret_len && memcmp(plaintext, secret, secret_len) == 0) {
        printf("  ✓ 解密结果与原始明文完全一致，机密性保护验证通过！\n");
    } else {
        printf("  ✗ 解密结果不一致，出现异常！\n");
        rv = SDR_UNKNOWERR;
    }

cleanup:
    if (hSession) SDF_CloseSession(hSession);
    if (hDevice)  SDF_CloseDevice(hDevice);

    printf("\n演示结束。\n");
    return (rv == SDR_OK) ? 0 : 1;
}
