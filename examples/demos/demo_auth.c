/**
 * demo_auth.c — 身份认证演示（外部 SM2 签名验签）
 *
 * 场景：
 *   "签名方"持有私钥，对一条消息生成数字签名，证明"这条消息确实由我发出"。
 *   "验证方"持有对应公钥，验证签名是否合法，从而确认消息来源可信、未被伪造。
 *
 * SM2 签名正确流程（GM/T 0018 §6.5）：
 *   1. 先计算消息摘要（SM3 哈希）
 *   2. 再用私钥对摘要签名（SGD_SM3_SM2 算法 ID 表示"输入已是摘要"）
 *   注意：若使用 SGD_SM2_1，库会自动在内部对数据做预处理（含 Z 值计算），
 *         两种方式结果不同，验签时需用相同算法 ID。
 *
 * 编译：见同目录 Makefile，执行 make demo_auth
 * 运行：./demo_auth
 *
 * 前提：可执行文件同目录下需有 config.toml（日志配置）
 */

#include <stdio.h>
#include <string.h>
#include "sdf.h"

/* ──────────────── 辅助：打印十六进制 ──────────────── */
static void print_hex(const char *label, const unsigned char *data, unsigned int len)
{
    printf("  %-10s: ", label);
    for (unsigned int i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) printf("\n              ");
    }
    printf("\n");
}

/* ──────────────── 辅助：用 SDF Hash 接口计算 SM3 摘要 ──────────────── */
static int sm3_hash(void *session,
                    const unsigned char *data, unsigned int data_len,
                    unsigned char *hash_out, unsigned int *hash_len)
{
    int rv;
    /*
     * HashInit：pucPublicKey=NULL, pucID=NULL 表示纯 SM3 哈希，
     * 不做 SM2 签名预处理（Z 值混入），适合"先手动哈希再签名"的场景。
     */
    rv = SDF_HashInit(session, SGD_SM3, NULL, NULL, 0);
    if (rv != SDR_OK) return rv;

    rv = SDF_HashUpdate(session, data, data_len);
    if (rv != SDR_OK) return rv;

    return SDF_HashFinal(session, hash_out, hash_len);
}

/* ──────────────────────────────────────────────────── */

int main(void)
{
    printf("========================================\n");
    printf("  身份认证演示：SM2 外部密钥签名验签\n");
    printf("========================================\n\n");

    void *hDevice  = NULL;
    void *hSession = NULL;
    int   rv       = SDR_OK;

    ECCrefPublicKey  pubKey;
    ECCrefPrivateKey priKey;
    ECCSignature     signature;
    unsigned char    digest[32]  = {0};
    unsigned int     digest_len  = 0;

    /* ── 打开设备和会话 ── */
    rv = SDF_OpenDevice(&hDevice);
    if (rv != SDR_OK) { printf("[ERROR] SDF_OpenDevice 失败 0x%08X\n", rv); return 1; }
    rv = SDF_OpenSession(hDevice, &hSession);
    if (rv != SDR_OK) { printf("[ERROR] SDF_OpenSession 失败 0x%08X\n", rv);
                        SDF_CloseDevice(hDevice); return 1; }
    printf("[OK]    打开设备和会话\n\n");

    /* ══════════════════════════════════════════
     * 第一阶段：密钥准备
     *
     * 外部密钥 = 在设备外部生成，以明文结构传入 SDK。
     * 适合测试和开发场景，不需要 mock_keys.toml 配置。
     *
     * 实际生产场景通常使用"内部密钥"（预存在设备中，
     * 私钥永不出设备）——使用 SDF_InternalSign_ECC 接口。
     * ══════════════════════════════════════════ */
    printf("【第一阶段：生成 SM2 密钥对】\n");

    /*
     * GenerateKeyPair_ECC：让设备随机生成一对 SM2 密钥。
     * 返回的 pubKey/priKey 是"外部密钥"结构，可在内存中直接使用。
     * 格式：x/y/K 各 64 字节，右对齐（SM2 实际值在后 32 字节，前 32 字节补零）。
     */
    rv = SDF_GenerateKeyPair_ECC(hSession, SGD_SM2_1, 256, &pubKey, &priKey);
    if (rv != SDR_OK) {
        printf("[ERROR] 生成 SM2 密钥对失败 0x%08X\n", rv);
        goto cleanup;
    }
    printf("[OK]    生成 SM2 密钥对\n");
    /* 实际值在后 32 字节（高位 32 字节为补零） */
    print_hex("公钥 X", pubKey.x + 32, 32);
    print_hex("公钥 Y", pubKey.y + 32, 32);
    print_hex("私钥 K", priKey.K + 32, 32);

    /* ══════════════════════════════════════════
     * 第二阶段：签名（签名方执行）
     *
     * SM2 签名的输入是 32 字节的消息摘要，不是原始消息。
     * 这里分两步：先 SM3 哈希，再 SM2 签名。
     * ══════════════════════════════════════════ */
    printf("\n【第二阶段：签名方对消息签名】\n");

    /* 待签名消息（模拟一条合同内容摘要） */
    const char *message = "合同编号:CONTRACT-2025-001,甲方:某科技公司,金额:500000元";
    unsigned int msg_len = (unsigned int)strlen(message);
    printf("  消息内容 : %s\n", message);

    /* 步骤 2a：计算消息的 SM3 摘要 */
    rv = sm3_hash(hSession,
                  (const unsigned char *)message, msg_len,
                  digest, &digest_len);
    if (rv != SDR_OK) {
        printf("[ERROR] 计算 SM3 摘要失败 0x%08X\n", rv);
        goto cleanup;
    }
    printf("[OK]    计算 SM3 摘要（32 字节）\n");
    print_hex("SM3 摘要", digest, digest_len);

    /* 步骤 2b：用私钥对摘要签名 */
    /*
     * 算法 ID 使用 SGD_SM3_SM2：表示输入的 32 字节是已经过 SM3 处理的摘要，
     * 库直接用它做 SM2 签名运算，不再做额外预处理。
     *
     * 对比：SGD_SM2_1 表示输入是原始消息，库内部会先做 Z 值混入再哈希再签名，
     * 适合一次性传入原始消息的场景。两种方式都正确，选一种并在签名和验签中保持一致。
     */
    rv = SDF_ExternalSign_ECC(hSession, SGD_SM3_SM2, &priKey,
                              digest, digest_len, &signature);
    if (rv != SDR_OK) {
        printf("[ERROR] SM2 签名失败 0x%08X\n", rv);
        goto cleanup;
    }
    printf("[OK]    SM2 签名完成\n");
    print_hex("签名 R", signature.r + 32, 32);
    print_hex("签名 S", signature.s + 32, 32);

    /* ══════════════════════════════════════════
     * 第三阶段：验签（验证方执行）
     *
     * 验证方拥有：原始消息 + 签名值 + 签名方公钥
     * 验证方不持有私钥。
     * ══════════════════════════════════════════ */
    printf("\n【第三阶段：验证方验证签名】\n");

    /* 步骤 3a：验证方独立重新计算消息摘要（不信任发送方传来的摘要） */
    unsigned char digest_verify[32] = {0};
    unsigned int  digest_verify_len = 0;

    rv = sm3_hash(hSession,
                  (const unsigned char *)message, msg_len,
                  digest_verify, &digest_verify_len);
    if (rv != SDR_OK) {
        printf("[ERROR] 验证方计算 SM3 摘要失败 0x%08X\n", rv);
        goto cleanup;
    }
    printf("[OK]    验证方重新计算 SM3 摘要\n");

    /* 步骤 3b：用公钥验签 */
    /*
     * ExternalVerify_ECC：传入公钥 + 摘要 + 签名，
     * 返回 SDR_OK 表示签名合法；返回 SDR_VERIFYERR 表示签名不合法。
     * 注意：算法 ID 必须与签名时使用的相同（SGD_SM3_SM2）。
     */
    rv = SDF_ExternalVerify_ECC(hSession, SGD_SM3_SM2, &pubKey,
                                digest_verify, digest_verify_len, &signature);
    printf("\n【验证结果】\n");
    if (rv == SDR_OK) {
        printf("  ✓ 签名验证通过！消息来源可信，内容未被篡改。\n");
    } else {
        printf("  ✗ 签名验证失败（错误码 0x%08X）\n", rv);
        goto cleanup;
    }

    /* ══════════════════════════════════════════
     * 第四阶段：模拟伪造攻击
     *
     * 攻击者篡改了消息内容，但没有私钥无法重新签名，
     * 验证方用原签名对篡改后消息验签，应当失败。
     * ══════════════════════════════════════════ */
    printf("\n【模拟伪造攻击】\n");
    const char *forged = "合同编号:CONTRACT-2025-001,甲方:某科技公司,金额:1元";
    printf("  篡改消息 : %s\n", forged);

    unsigned char digest_forged[32] = {0};
    unsigned int  digest_forged_len = 0;
    sm3_hash(hSession,
             (const unsigned char *)forged, (unsigned int)strlen(forged),
             digest_forged, &digest_forged_len);

    /* 攻击者用原来的签名对篡改后的消息做验签，期望验签失败 */
    int forged_rv = SDF_ExternalVerify_ECC(hSession, SGD_SM3_SM2, &pubKey,
                                            digest_forged, digest_forged_len, &signature);
    if (forged_rv == SDR_VERIFYERR || forged_rv != SDR_OK) {
        printf("  ✓ 伪造消息验签失败（错误码 0x%08X），攻击被成功阻止！\n", forged_rv);
    } else {
        printf("  ✗ 异常：伪造消息验签竟然成功，存在安全漏洞！\n");
        rv = SDR_UNKNOWERR;
    }

cleanup:
    if (hSession) SDF_CloseSession(hSession);
    if (hDevice)  SDF_CloseDevice(hDevice);

    printf("\n演示结束。\n");
    return (rv == SDR_OK) ? 0 : 1;
}
