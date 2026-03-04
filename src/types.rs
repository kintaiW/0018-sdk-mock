// GM/T 0018-2023 标准数据结构定义
// 所有结构体使用 #[repr(C)] 确保与 C 语言内存布局一致

/// 设备信息结构（GM/T 0018 §6.2.1）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DEVICEINFO {
    /// 发行厂商名称（UTF-8，40字节）
    pub IssuerName: [u8; 40],
    /// 设备名称（UTF-8，16字节）
    pub DeviceName: [u8; 16],
    /// 设备序列号（UTF-8，16字节）
    pub DeviceSerial: [u8; 16],
    /// 设备版本号
    pub DeviceVersion: u32,
    /// 标准版本号
    pub StandardVersion: u32,
    /// 非对称算法能力（[签名类, 加解密类]）
    pub AsymAlgAbility: [u32; 2],
    /// 对称算法能力
    pub SymAlgAbility: u32,
    /// 哈希算法能力
    pub HashAlgAbility: u32,
    /// 支持的最大文件存储空间（字节）
    pub BufferSize: u32,
}

impl Default for DEVICEINFO {
    fn default() -> Self {
        Self {
            IssuerName: [0u8; 40],
            DeviceName: [0u8; 16],
            DeviceSerial: [0u8; 16],
            DeviceVersion: 0x00010000,   // v1.0
            StandardVersion: 0x00020000, // GM/T 0018-2023
            AsymAlgAbility: [0x00000400, 0x00000400], // SM2
            SymAlgAbility: 0x00000400,   // SM4
            HashAlgAbility: 0x00000400,  // SM3
            BufferSize: 64 * 1024,       // 64KB
        }
    }
}

/// ECC 公钥（GM/T 0018 §6.2.2.4）
/// bits 指定密钥长度（SM2 = 256）
/// x, y 为 64 字节右对齐大端坐标（高位补零）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCrefPublicKey {
    pub bits: u32,
    pub x: [u8; 64],
    pub y: [u8; 64],
}

impl Default for ECCrefPublicKey {
    fn default() -> Self {
        Self { bits: 256, x: [0u8; 64], y: [0u8; 64] }
    }
}

/// ECC 私钥（GM/T 0018 §6.2.2.4）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCrefPrivateKey {
    pub bits: u32,
    pub K: [u8; 64],
}

impl Default for ECCrefPrivateKey {
    fn default() -> Self {
        Self { bits: 256, K: [0u8; 64] }
    }
}

/// ECC 密文结构（GM/T 0018 §6.2.2.5）
/// 对应 SM2 加密输出：C1（点坐标）‖ C3（SM3哈希）‖ C2（密文）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ECCCipher {
    /// C1.x（64字节，右对齐大端）
    pub x: [u8; 64],
    /// C1.y（64字节，右对齐大端）
    pub y: [u8; 64],
    /// C3 = SM3(x2‖M‖y2)（32字节）
    pub M: [u8; 32],
    /// C2 密文数据长度（字节）
    pub L: u32,
    /// C2 密文数据（最大136字节）
    pub C: [u8; 136],
}

impl Default for ECCCipher {
    fn default() -> Self {
        Self { x: [0u8; 64], y: [0u8; 64], M: [0u8; 32], L: 0, C: [0u8; 136] }
    }
}

/// ECC 签名结构（GM/T 0018 §6.2.2.5）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCSignature {
    pub r: [u8; 64],
    pub s: [u8; 64],
}

impl Default for ECCSignature {
    fn default() -> Self {
        Self { r: [0u8; 64], s: [0u8; 64] }
    }
}

/// SM2 密钥交换数据（GM/T 0018 §6.2.2.6）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCrefExchangeData {
    /// 临时公钥
    pub tmpPubKey: ECCrefPublicKey,
    /// Z 值（SM3 摘要）
    pub z: [u8; 32],
}

/// 对称算法标识（GM/T 0018 §5.2）
pub mod alg_id {
    pub const SGD_SM1_ECB: u32 = 0x00000101;
    pub const SGD_SM1_CBC: u32 = 0x00000102;
    pub const SGD_SM1_CFB: u32 = 0x00000104;
    pub const SGD_SM1_OFB: u32 = 0x00000108;
    pub const SGD_SM1_MAC: u32 = 0x00000110;

    pub const SGD_SM4_ECB: u32 = 0x00000401;
    pub const SGD_SM4_CBC: u32 = 0x00000402;
    pub const SGD_SM4_CFB: u32 = 0x00000404;
    pub const SGD_SM4_OFB: u32 = 0x00000408;
    pub const SGD_SM4_MAC: u32 = 0x00000410;
    pub const SGD_SM4_CTR: u32 = 0x00000420;
    // Reason: sdfc 标准 SGD_SM4_GCM = 0x00000480，0x00000440 为 XTS（本 Mock 不支持）
    pub const SGD_SM4_GCM: u32 = 0x00000480;
    pub const SGD_SM4_CCM: u32 = 0x00000440; // XTS 位置，保留常量避免编译错误

    pub const SGD_SM2_1: u32 = 0x00020200; // SM2 签名
    pub const SGD_SM2_2: u32 = 0x00020400; // SM2 密钥交换
    pub const SGD_SM2_3: u32 = 0x00020800; // SM2 加密
    // Reason: sdfc 用 SGD_SM2=0x00020100 统一表示 SM2 椭圆曲线算法（sign/verify/keygen均用此值）
    pub const SGD_SM2: u32 = 0x00020100;   // SM2 通用标识（等同签名算法）

    pub const SGD_SM3: u32 = 0x00000001;  // SM3 哈希
    pub const SGD_SHA1: u32 = 0x00000002;
    pub const SGD_SHA256: u32 = 0x00000004;
}
