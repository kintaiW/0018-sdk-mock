// GM/T 0018-2023 标准错误码定义
// 参考：GM/T 0018 §5.3 错误代码

/// 操作成功
pub const SDR_OK: i32 = 0x00000000;

/// 设备内部未知错误
pub const SDR_UNKNOWERR: i32 = 0x01000001u32 as i32;
/// 设备不支持该功能
pub const SDR_NOTSUPPORT: i32 = 0x01000002u32 as i32;
/// 调用者未获得授权
pub const SDR_COMMFAIL: i32 = 0x01000003u32 as i32;
/// 硬件故障
pub const SDR_HARDFAIL: i32 = 0x01000004u32 as i32;
/// 打开设备失败
pub const SDR_OPENDEVICE: i32 = 0x01000005u32 as i32;
/// 打开密码设备会话句柄失败
pub const SDR_OPENSESSION: i32 = 0x01000006u32 as i32;
/// 申请内存失败
pub const SDR_PARDENY: i32 = 0x01000007u32 as i32;
/// 密钥句柄无效
pub const SDR_KEYNOTEXIST: i32 = 0x01000008u32 as i32;
/// 未经许可的会话
pub const SDR_ALGNOTSUPPORT: i32 = 0x01000009u32 as i32;
/// 算法操作失败
pub const SDR_ALGMODNOTSUPPORT: i32 = 0x0100000Au32 as i32;
/// 设备已打开
pub const SDR_PKOPERR: i32 = 0x0100000Bu32 as i32;
/// Hash操作失败
pub const SDR_SKOPERR: i32 = 0x0100000Cu32 as i32;
/// 签名失败
pub const SDR_SIGNERR: i32 = 0x0100000Du32 as i32;
/// 验签失败
pub const SDR_VERIFYERR: i32 = 0x0100000Eu32 as i32;
/// 对称算法运算失败
pub const SDR_SYMOPERR: i32 = 0x0100000Fu32 as i32;
/// 解密失败
pub const SDR_STEPERR: i32 = 0x01000010u32 as i32;
/// 文件操作失败
pub const SDR_FILESIZEERR: i32 = 0x01000011u32 as i32;
/// 文件不存在
pub const SDR_FILENOEXIST: i32 = 0x01000012u32 as i32;
/// 文件已存在
pub const SDR_FILEOFSET: i32 = 0x01000013u32 as i32;
/// 密钥类型错误
pub const SDR_KEYTYPEERR: i32 = 0x01000014u32 as i32;
/// 密钥已存在
pub const SDR_KEYERR: i32 = 0x01000015u32 as i32;
/// ECC 密钥类型或长度不符合
pub const SDR_ENCDATAERR: i32 = 0x01000016u32 as i32;
/// 内存不足
pub const SDR_RANDERR: i32 = 0x01000017u32 as i32;
/// 哈希运算失败
pub const SDR_PRNGERR: i32 = 0x01000018u32 as i32;
/// 密钥索引越界
pub const SDR_KEYINDEX: i32 = 0x01000019u32 as i32;
/// 无效的会话句柄
pub const SDR_INVALIDHANDLE: i32 = 0x0100001Au32 as i32;
/// 参数错误（指针为空、长度非法等）
pub const SDR_PARAMERR: i32 = 0x01000100u32 as i32;
/// 配置文件错误
pub const SDR_CONFIGERR: i32 = 0x01000101u32 as i32;
/// 内存分配失败
pub const SDR_MEMERR: i32 = 0x01000102u32 as i32;
