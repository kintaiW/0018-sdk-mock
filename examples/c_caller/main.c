/**
 * main.c — GM/T 0018 Mock SDK C 语言调用示例
 *
 * 演示内容：
 *   1. 打开设备与会话
 *   2. 生成随机数
 *   3. SM3 哈希（HashInit / HashUpdate / HashFinal）
 *   4. SM2 外部密钥签名与验签
 *   5. SM2 外部公钥加密与私钥解密
 *   6. SM4-CBC 加密与解密（KEK 保护会话密钥）
 *   7. HMAC-SM3 计算
 *   8. 关闭会话与设备
 *
 * 编译（Linux）：
 *   gcc -o demo main.c -I../../ -L../../target/debug -lsdf_mock -Wl,-rpath,../../target/debug
 *
 * 编译（Windows MinGW）：
 *   gcc -o demo.exe main.c -I../../ -L../../target/debug -lsdf_mock
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../sdf.h"

/* 工具：十六进制打印 */
static void print_hex(const char *label, const unsigned char *buf, unsigned int len) {
    printf("  %s [%u bytes]: ", label, len);
    for (unsigned int i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

/* 工具：检查返回值，失败则退出 */
static void check(const char *name, int ret) {
    if (ret != SDR_OK) {
        fprintf(stderr, "[FAIL] %s returned 0x%08X\n", name, (unsigned int)ret);
        exit(1);
    }
    printf("[OK]   %s\n", name);
}

int main(void) {
    void *hDevice  = NULL;
    void *hSession = NULL;
    int   ret;

    printf("=== GM/T 0018 Mock SDK Demo ===\n\n");

    /* ── 1. 打开设备与会话 ──────────────────────────────── */
    printf("--- 1. 设备初始化 ---\n");
    check("SDF_OpenDevice",  SDF_OpenDevice(&hDevice));
    check("SDF_OpenSession", SDF_OpenSession(hDevice, &hSession));

    /* ── 2. 获取设备信息 ──────────────────────────────── */
    printf("\n--- 2. 设备信息 ---\n");
    DEVICEINFO info;
    memset(&info, 0, sizeof(info));
    check("SDF_GetDeviceInfo", SDF_GetDeviceInfo(hSession, &info));
    printf("  IssuerName:      %.40s\n", info.IssuerName);
    printf("  DeviceName:      %.16s\n", info.DeviceName);
    printf("  DeviceSerial:    %.16s\n", info.DeviceSerial);
    printf("  DeviceVersion:   0x%08X\n", info.DeviceVersion);
    printf("  StandardVersion: 0x%08X\n", info.StandardVersion);

    /* ── 3. 生成随机数 ──────────────────────────────── */
    printf("\n--- 3. 随机数 ---\n");
    unsigned char random_buf[32];
    check("SDF_GenerateRandom", SDF_GenerateRandom(hSession, sizeof(random_buf), random_buf));
    print_hex("Random", random_buf, sizeof(random_buf));

    /* ── 4. SM3 哈希 ──────────────────────────────── */
    printf("\n--- 4. SM3 哈希 ---\n");
    const unsigned char msg[] = "Hello, GM/T 0018!";
    unsigned int msg_len = (unsigned int)strlen((const char *)msg);

    check("SDF_HashInit",   SDF_HashInit(hSession, SGD_SM3, NULL, NULL, 0));
    check("SDF_HashUpdate", SDF_HashUpdate(hSession, msg, msg_len));

    unsigned char hash[32];
    unsigned int  hash_len = 0;
    check("SDF_HashFinal",  SDF_HashFinal(hSession, hash, &hash_len));
    print_hex("SM3(msg)", hash, hash_len);

    /* ── 5. SM2 外部密钥对生成 ──────────────────────────────── */
    printf("\n--- 5. SM2 签名与验签 ---\n");
    ECCrefPublicKey  ext_pub;
    ECCrefPrivateKey ext_pri;
    memset(&ext_pub, 0, sizeof(ext_pub));
    memset(&ext_pri, 0, sizeof(ext_pri));

    check("SDF_GenerateKeyPair_ECC",
          SDF_GenerateKeyPair_ECC(hSession, SGD_SM2_1, 256, &ext_pub, &ext_pri));

    /* 对 SM3 哈希值（32字节）做外部签名 */
    ECCSignature sig;
    memset(&sig, 0, sizeof(sig));
    check("SDF_ExternalSign_ECC",
          SDF_ExternalSign_ECC(hSession, SGD_SM2_1, &ext_pri, hash, hash_len, &sig));
    print_hex("Sig.r", sig.r + 32, 32);
    print_hex("Sig.s", sig.s + 32, 32);

    /* 验签 */
    check("SDF_ExternalVerify_ECC",
          SDF_ExternalVerify_ECC(hSession, SGD_SM2_1, &ext_pub, hash, hash_len, &sig));

    /* ── 6. SM2 外部加密与解密 ──────────────────────────────── */
    printf("\n--- 6. SM2 加密/解密 ---\n");
    const unsigned char plaintext[] = "SM2 encrypt test";
    unsigned int pt_len = (unsigned int)strlen((const char *)plaintext);

    ECCCipher cipher;
    memset(&cipher, 0, sizeof(cipher));
    check("SDF_ExternalEncrypt_ECC",
          SDF_ExternalEncrypt_ECC(hSession, SGD_SM2_3, &ext_pub,
                                   plaintext, pt_len, &cipher));
    printf("  Cipher.L = %u\n", cipher.L);

    unsigned char decrypted[256];
    unsigned int  dec_len = 0;
    memset(decrypted, 0, sizeof(decrypted));
    check("SDF_ExternalDecrypt_ECC",
          SDF_ExternalDecrypt_ECC(hSession, SGD_SM2_3, &ext_pri,
                                   &cipher, decrypted, &dec_len));
    printf("  Decrypted [%u]: %.*s\n", dec_len, dec_len, decrypted);

    /* ── 7. SM4-CBC 加密/解密（KEK 保护会话密钥） ──────────────── */
    printf("\n--- 7. SM4-CBC 加密/解密 ---\n");

    /* 生成 KEK 保护的会话密钥（需要 mock_keys.toml 中配置 KEK 索引1） */
    unsigned char kek_cipher[64];
    unsigned int  kek_cipher_len = sizeof(kek_cipher);
    void         *hKey = NULL;

    ret = SDF_GenerateKeyWithKEK(hSession, 128, SGD_SM4_ECB, 1,
                                  kek_cipher, &kek_cipher_len, &hKey);
    if (ret == SDR_OK) {
        print_hex("KEK-wrapped key", kek_cipher, kek_cipher_len);

        const unsigned char iv[16]   = {0x00};
        const unsigned char sm4_pt[] = "0123456789ABCDEF"; /* 16字节 */
        unsigned int sm4_pt_len = 16;

        unsigned char sm4_ct[32];
        unsigned int  sm4_ct_len = 0;
        check("SDF_Encrypt (SM4-CBC)",
              SDF_Encrypt(hSession, hKey, SGD_SM4_CBC, iv,
                           sm4_pt, sm4_pt_len, sm4_ct, &sm4_ct_len));
        print_hex("SM4-CBC ciphertext", sm4_ct, sm4_ct_len);

        unsigned char sm4_pt2[32];
        unsigned int  sm4_pt2_len = 0;
        check("SDF_Decrypt (SM4-CBC)",
              SDF_Decrypt(hSession, hKey, SGD_SM4_CBC, iv,
                           sm4_ct, sm4_ct_len, sm4_pt2, &sm4_pt2_len));
        printf("  Decrypted [%u]: %.*s\n", sm4_pt2_len, sm4_pt2_len, sm4_pt2);

        /* HMAC-SM3 使用同一会话密钥 */
        printf("\n--- 8. HMAC-SM3 ---\n");
        check("SDF_HMACInit",   SDF_HMACInit(hSession, hKey, SGD_SM3));
        check("SDF_HMACUpdate", SDF_HMACUpdate(hSession, msg, msg_len));

        unsigned char hmac[32];
        unsigned int  hmac_len = 0;
        check("SDF_HMACFinal",  SDF_HMACFinal(hSession, hmac, &hmac_len));
        print_hex("HMAC-SM3", hmac, hmac_len);

        SDF_DestroyKey(hSession, hKey);
    } else {
        printf("[SKIP] SDF_GenerateKeyWithKEK: 需要配置 mock_keys.toml 中的 KEK（错误码 0x%08X���\n",
               (unsigned int)ret);
    }

    /* ── 9. 关闭 ──────────────────────────────── */
    printf("\n--- 9. 关闭设备 ---\n");
    check("SDF_CloseSession", SDF_CloseSession(hSession));
    check("SDF_CloseDevice",  SDF_CloseDevice(hDevice));

    printf("\n=== 全部演示完成 ===\n");
    return 0;
}
