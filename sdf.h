/**
 * sdf.h — GM/T 0018-2023 密码设备应用接口（Mock 实现）
 *
 * 本头文件对应 libsdf_mock.so / sdf_mock.dll 动态库的 C 接口声明。
 * 数据结构与常量严格遵循 GM/T 0018-2023 标准。
 */

#ifndef SDF_H
#define SDF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ============================================================
 *  平台兼容：符号导出
 * ============================================================ */
#if defined(_WIN32) || defined(_WIN64)
#  define SDF_API __declspec(dllimport)
#else
#  define SDF_API
#endif

/* ============================================================
 *  错误码（GM/T 0018 §5.3）
 * ============================================================ */
#define SDR_OK               0x00000000  /* 操作成功               */
#define SDR_UNKNOWERR        0x01000001  /* 未知错误               */
#define SDR_NOTSUPPORT       0x01000002  /* 不支持该功能           */
#define SDR_COMMFAIL         0x01000003  /* 通信失败               */
#define SDR_HARDFAIL         0x01000004  /* 硬件故障               */
#define SDR_OPENDEVICE       0x01000005  /* 打开设备失败           */
#define SDR_OPENSESSION      0x01000006  /* 打开会话失败           */
#define SDR_PARDENY          0x01000007  /* 申请内存失败/权限拒绝  */
#define SDR_KEYNOTEXIST      0x01000008  /* 密钥不存在             */
#define SDR_ALGNOTSUPPORT    0x01000009  /* 算法不支持             */
#define SDR_ALGMODNOTSUPPORT 0x0100000A  /* 算法模式不支持         */
#define SDR_PKOPERR          0x0100000B  /* 公钥运算失败           */
#define SDR_SKOPERR          0x0100000C  /* 私钥运算失败           */
#define SDR_SIGNERR          0x0100000D  /* 签名失败               */
#define SDR_VERIFYERR        0x0100000E  /* 验签失败               */
#define SDR_SYMOPERR         0x0100000F  /* 对称运算失败           */
#define SDR_STEPERR          0x01000010  /* 步骤错误               */
#define SDR_FILESIZEERR      0x01000011  /* 文件大小错误           */
#define SDR_FILENOEXIST      0x01000012  /* 文件不存在             */
#define SDR_FILEOFSET        0x01000013  /* 文件偏移错误           */
#define SDR_KEYTYPEERR       0x01000014  /* 密钥类型错误           */
#define SDR_KEYERR           0x01000015  /* 密钥错误               */
#define SDR_ENCDATAERR       0x01000016  /* 加密数据错误           */
#define SDR_RANDERR          0x01000017  /* 随机数错误             */
#define SDR_PRNGERR          0x01000018  /* 随机数发生器错误       */
#define SDR_KEYINDEX         0x01000019  /* 密钥索引越界           */
#define SDR_INVALIDHANDLE    0x0100001A  /* 无效句柄               */
#define SDR_PARAMERR         0x01000100  /* 参数错误               */
#define SDR_CONFIGERR        0x01000101  /* 配置错误               */
#define SDR_MEMERR           0x01000102  /* 内存分配失败           */

/* ============================================================
 *  算法标识（GM/T 0018 §5.2）
 * ============================================================ */
/* SM4 对称算法 */
#define SGD_SM4_ECB  0x00000401
#define SGD_SM4_CBC  0x00000402
#define SGD_SM4_CFB  0x00000404
#define SGD_SM4_OFB  0x00000408
#define SGD_SM4_MAC  0x00000410
#define SGD_SM4_CTR  0x00000420
#define SGD_SM4_GCM  0x00000440
#define SGD_SM4_CCM  0x00000480

/* SM2 非对称算法 */
#define SGD_SM2_1    0x00020200  /* SM2 签名       */
#define SGD_SM2_2    0x00020400  /* SM2 密钥交换   */
#define SGD_SM2_3    0x00020800  /* SM2 加密       */

/* 哈希算法 */
#define SGD_SM3      0x00000001
#define SGD_SHA1     0x00000002
#define SGD_SHA256   0x00000004

/* ============================================================
 *  数据结构（GM/T 0018 §6.2）
 * ============================================================ */

/** 设备信息（GM/T 0018 §6.2.1） */
typedef struct {
    uint8_t  IssuerName[40];    /* 发行厂商名称（UTF-8）         */
    uint8_t  DeviceName[16];    /* 设备名称（UTF-8）             */
    uint8_t  DeviceSerial[16];  /* 设备序列号（UTF-8）           */
    uint32_t DeviceVersion;     /* 设备版本号                    */
    uint32_t StandardVersion;   /* 标准版本号                    */
    uint32_t AsymAlgAbility[2]; /* 非对称算法能力                */
    uint32_t SymAlgAbility;     /* 对称算法能力                  */
    uint32_t HashAlgAbility;    /* 哈希算法能力                  */
    uint32_t BufferSize;        /* 支持的最大缓冲区（字节）      */
} DEVICEINFO;

/** ECC 公钥（GM/T 0018 §6.2.2.4）
 *  x/y 各 64 字节，右对齐大端（SM2 使用后 32 字节，高位补零） */
typedef struct {
    uint32_t bits;   /* 密钥长度，SM2 = 256 */
    uint8_t  x[64];
    uint8_t  y[64];
} ECCrefPublicKey;

/** ECC 私钥（GM/T 0018 §6.2.2.4）
 *  K 为 64 字节，右对齐大端（SM2 使用后 32 字节，高位补零） */
typedef struct {
    uint32_t bits;   /* 密钥长度，SM2 = 256 */
    uint8_t  K[64];
} ECCrefPrivateKey;

/** ECC 密文（GM/T 0018 §6.2.2.5）
 *  对应 SM2 加密输出 C1‖C3‖C2 格式 */
typedef struct {
    uint8_t  x[64];    /* C1.x（右对齐大端）  */
    uint8_t  y[64];    /* C1.y（右对齐大端）  */
    uint8_t  M[32];    /* C3 = SM3(x2‖M‖y2)   */
    uint32_t L;        /* C2 密文长度（字节）  */
    uint8_t  C[136];   /* C2 密文数据（最大 136 字节） */
} ECCCipher;

/** ECC 签名（GM/T 0018 §6.2.2.5）
 *  r/s 各 64 字节，右对齐大端 */
typedef struct {
    uint8_t r[64];
    uint8_t s[64];
} ECCSignature;

/* ============================================================
 *  设备管理接口（GM/T 0018 §6.3）
 * ============================================================ */

/**
 * SDF_OpenDevice — 打开设备
 * @param phDeviceHandle [out] 设备句柄（Mock 固定输出 0x1）
 * @return SDR_OK 或错误码
 */
SDF_API int SDF_OpenDevice(void **phDeviceHandle);

/**
 * SDF_CloseDevice — 关闭设备
 * @param hDeviceHandle [in] 设备句柄（Mock 忽略）
 */
SDF_API int SDF_CloseDevice(void *hDeviceHandle);

/**
 * SDF_OpenSession — 打开会话，返回会话句柄
 * @param hDeviceHandle  [in]  设备句柄
 * @param phSessionHandle [out] 会话句柄
 */
SDF_API int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);

/**
 * SDF_CloseSession — 关闭会话
 * @param hSessionHandle [in] 会话句柄
 */
SDF_API int SDF_CloseSession(void *hSessionHandle);

/**
 * SDF_GetDeviceInfo — 获取设备信息
 * @param hSessionHandle [in]  会话句柄
 * @param pstDeviceInfo  [out] 设备信息结构
 */
SDF_API int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);

/* ============================================================
 *  密钥管理接口（GM/T 0018 §6.4）
 * ============================================================ */

/**
 * SDF_GenerateRandom — 生成随机数
 * @param hSessionHandle [in]  会话句柄
 * @param uiLength       [in]  随机数长度（字节）
 * @param pucRandom      [out] 随机数缓冲区（调用者分配）
 */
SDF_API int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                               unsigned char *pucRandom);

/**
 * SDF_GetPrivateKeyAccessRight — 获取内部私钥使用权限（Mock 直接授权）
 * @param hSessionHandle [in] 会话句柄
 * @param uiKeyIndex     [in] 密钥索引（从 1 开始）
 * @param pucPassword    [in] 口令（Mock 忽略）
 * @param uiPwdLength    [in] 口令长度
 */
SDF_API int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex,
                                         const unsigned char *pucPassword,
                                         unsigned int uiPwdLength);

/**
 * SDF_ReleasePrivateKeyAccessRight — 释放内部私钥使用权限
 */
SDF_API int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex);

/**
 * SDF_ExportSignPublicKey_ECC — 导出内部 SM2 签名公钥
 * @param uiKeyIndex  [in]  密钥索引（从 1 开始）
 * @param pucPublicKey [out] 公钥结构
 */
SDF_API int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                                        ECCrefPublicKey *pucPublicKey);

/**
 * SDF_ExportEncPublicKey_ECC — 导出内部 SM2 加密公钥
 */
SDF_API int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                                       ECCrefPublicKey *pucPublicKey);

/**
 * SDF_GenerateKeyPair_ECC — 生成临时 SM2 密钥对
 * @param uiAlgID      [in]  算法标识（SGD_SM2_1/3）
 * @param uiKeyBits    [in]  密钥长度（256）
 * @param pucPublicKey  [out] 公钥
 * @param pucPrivateKey [out] 私钥
 */
SDF_API int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                    unsigned int uiKeyBits,
                                    ECCrefPublicKey *pucPublicKey,
                                    ECCrefPrivateKey *pucPrivateKey);

/**
 * SDF_GenerateKeyWithKEK — 生成会话密钥并用 KEK 加密保护
 * @param uiLength    [in]  会话密钥长度（字节，SM4 = 16）
 * @param uiAlgID     [in]  保留（标准参数，Mock 忽略）
 * @param uiKEKIndex  [in]  KEK 索引（从 1 开始）
 * @param pucKey      [out] 加密后的密钥密文（调用者需分配足够空间）
 * @param puiKeyLength [out] 密文长度
 * @param phKeyHandle  [out] 会话密钥句柄
 */
SDF_API int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiLength,
                                   unsigned int uiAlgID, unsigned int uiKEKIndex,
                                   unsigned char *pucKey, unsigned int *puiKeyLength,
                                   void **phKeyHandle);

/**
 * SDF_ImportKeyWithKEK — 导入 KEK 保护的会话密钥
 * @param uiAlgID    [in]  密钥算法标识
 * @param uiKEKIndex [in]  KEK 索引
 * @param pucKey     [in]  加密后的密钥密文
 * @param uiKeyLength [in] 密文长度
 * @param phKeyHandle [out] 会话密钥句柄
 */
SDF_API int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                                 unsigned int uiKEKIndex, const unsigned char *pucKey,
                                 unsigned int uiKeyLength, void **phKeyHandle);

/**
 * SDF_GenerateKeyWithIPK_ECC — 生成会话密钥并用内部 SM2 加密公钥保护
 * @param uiIPKIndex  [in]  内部加密密钥索引
 * @param uiKeyBits   [in]  会话密钥长度（位）
 * @param pucKey      [out] SM2 密文结构
 * @param phKeyHandle  [out] 会话密钥句柄
 */
SDF_API int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, unsigned int uiIPKIndex,
                                       unsigned int uiKeyBits, ECCCipher *pucKey,
                                       void **phKeyHandle);

/**
 * SDF_ImportKeyWithISK_ECC — 导入内部 SM2 私钥解密保护的会话密钥
 * @param uiISKIndex  [in]  内部加密私钥索引
 * @param pucKey      [in]  SM2 密文结构
 * @param phKeyHandle  [out] 会话密钥句柄
 */
SDF_API int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                     const ECCCipher *pucKey, void **phKeyHandle);

/**
 * SDF_DestroyKey — 销毁会话密钥句柄
 * @param hKeyHandle [in] 会话密钥句柄
 */
SDF_API int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);

/* ============================================================
 *  非对称密码运算接口（GM/T 0018 §6.5）
 * ============================================================ */

/**
 * SDF_ExternalSign_ECC — 外部 SM2 签名（使用外部私钥）
 * @param uiAlgID       [in]  算法标识（SGD_SM2_1）
 * @param pucPrivateKey  [in]  外部私钥
 * @param pucData        [in]  待签名数据（32字节哈希值）
 * @param uiDataLength   [in]  数据长度
 * @param pucSignature   [out] 签名值
 */
SDF_API int SDF_ExternalSign_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                  const ECCrefPrivateKey *pucPrivateKey,
                                  const unsigned char *pucData, unsigned int uiDataLength,
                                  ECCSignature *pucSignature);

/**
 * SDF_ExternalVerify_ECC — 外部 SM2 验签（使用外部公钥）
 */
SDF_API int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                    const ECCrefPublicKey *pucPublicKey,
                                    const unsigned char *pucData, unsigned int uiDataLength,
                                    const ECCSignature *pucSignature);

/**
 * SDF_InternalSign_ECC — 内部 SM2 签名（使用内部签名私钥，需先授权）
 * @param uiISKIndex  [in]  内部签名私钥索引（从 1 开始）
 * @param pucData     [in]  原始消息数据
 * @param uiDataLength [in] 数据长度
 * @param pucSignature [out] 签名值
 */
SDF_API int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  const unsigned char *pucData, unsigned int uiDataLength,
                                  ECCSignature *pucSignature);

/**
 * SDF_InternalVerify_ECC — 内部 SM2 验签（使用内部加密公钥）
 * @param uiIPKIndex  [in] 内部公钥索引（从 1 开始）
 */
SDF_API int SDF_InternalVerify_ECC(void *hSessionHandle, unsigned int uiIPKIndex,
                                    const unsigned char *pucData, unsigned int uiDataLength,
                                    const ECCSignature *pucSignature);

/**
 * SDF_ExternalEncrypt_ECC — 外部 SM2 公钥加密
 * @param pucPublicKey [in]  外部公钥
 * @param pucData      [in]  明文（最大 136 字节）
 * @param uiDataLength  [in] 明文长度
 * @param pucEncData   [out] 密文结构
 */
SDF_API int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                     const ECCrefPublicKey *pucPublicKey,
                                     const unsigned char *pucData, unsigned int uiDataLength,
                                     ECCCipher *pucEncData);

/**
 * SDF_ExternalDecrypt_ECC — 外部 SM2 私钥解密
 * @param pucPrivateKey [in]  外部私钥
 * @param pucEncData    [in]  密文结构
 * @param pucData       [out] 明文缓冲区（调用者分配）
 * @param puiDataLength [out] 明文长度
 */
SDF_API int SDF_ExternalDecrypt_ECC(void *hSessionHandle, unsigned int uiAlgID,
                                     const ECCrefPrivateKey *pucPrivateKey,
                                     const ECCCipher *pucEncData,
                                     unsigned char *pucData, unsigned int *puiDataLength);

/* ============================================================
 *  对称密码运算接口（GM/T 0018 §6.6）
 * ============================================================ */

/**
 * SDF_Encrypt — 对称加密
 * @param hKeyHandle      [in]  会话密钥句柄
 * @param uiAlgID         [in]  算法标识（SGD_SM4_CBC 等）
 * @param pucIV           [in]  IV（ECB 模式可为 NULL；长度 16）
 * @param pucData         [in]  明文
 * @param uiDataLength    [in]  明文长度
 * @param pucEncData      [out] 密文缓冲区（调用者分配）
 * @param puiEncDataLength [out] 密文长度
 */
SDF_API int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                        const unsigned char *pucIV,
                        const unsigned char *pucData, unsigned int uiDataLength,
                        unsigned char *pucEncData, unsigned int *puiEncDataLength);

/**
 * SDF_Decrypt — 对称解密
 */
SDF_API int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                        const unsigned char *pucIV,
                        const unsigned char *pucEncData, unsigned int uiEncDataLength,
                        unsigned char *pucData, unsigned int *puiDataLength);

/**
 * SDF_CalculateMAC — 计算 SM4-CBC-MAC（16 字节）
 * @param uiAlgID      [in]  算法标识（SGD_SM4_MAC）
 * @param pucIV        [in]  IV（长度 16）
 * @param pucData      [in]  消息数据
 * @param uiDataLength [in]  消息长度（须为 16 的倍数）
 * @param pucMAC       [out] MAC 值（16 字节）
 * @param puiMACLength  [out] MAC 长度
 */
SDF_API int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                              const unsigned char *pucIV,
                              const unsigned char *pucData, unsigned int uiDataLength,
                              unsigned char *pucMAC, unsigned int *puiMACLength);

/* ============================================================
 *  哈希运算接口（GM/T 0018 §6.7）
 * ============================================================ */

/**
 * SDF_HashInit — 初始化哈希运算
 * @param uiAlgID    [in] 算法标识（SGD_SM3）
 * @param pucPublicKey [in] SM2 公钥（SM2 签名哈希时使用，可为 NULL）
 * @param pucID      [in] 用户 ID（SM2 签名哈希时使用，可为 NULL 则默认 "1234567812345678"）
 * @param uiIDLength  [in] ID 长度
 */
SDF_API int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID,
                          const ECCrefPublicKey *pucPublicKey,
                          const unsigned char *pucID, unsigned int uiIDLength);

/**
 * SDF_HashUpdate — 追加哈希数据
 */
SDF_API int SDF_HashUpdate(void *hSessionHandle,
                            const unsigned char *pucData, unsigned int uiDataLength);

/**
 * SDF_HashFinal — 完成哈希运算，输出 32 字节 SM3 摘要
 * @param pucHash      [out] 哈希值（32 字节）
 * @param puiHashLength [out] 哈希长度
 */
SDF_API int SDF_HashFinal(void *hSessionHandle,
                           unsigned char *pucHash, unsigned int *puiHashLength);

/**
 * SDF_HMACInit — 初始化 HMAC-SM3 运算
 * @param hKeyHandle [in] 会话密钥句柄（用作 HMAC 密钥）
 * @param uiAlgID    [in] 算法标识（SGD_SM3）
 */
SDF_API int SDF_HMACInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID);

/**
 * SDF_HMACUpdate — 追加 HMAC 数据
 */
SDF_API int SDF_HMACUpdate(void *hSessionHandle,
                            const unsigned char *pucData, unsigned int uiDataLength);

/**
 * SDF_HMACFinal — 完成 HMAC 运算，输出 32 字节 HMAC-SM3
 * @param pucMAC      [out] HMAC 值（32 字节）
 * @param puiMACLength [out] HMAC 长度
 */
SDF_API int SDF_HMACFinal(void *hSessionHandle,
                           unsigned char *pucMAC, unsigned int *puiMACLength);

#ifdef __cplusplus
}
#endif

#endif /* SDF_H */
