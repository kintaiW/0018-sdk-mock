// 密钥管理接口实现
use crate::error_code::*;
use crate::sdf_impl::device::with_session;
use crate::key_mgr::{KeyType, KeyData};
use crate::crypto::{sm2_keygen, generate_random, sm4_encrypt as sm4_enc, sm4_decrypt as sm4_dec};
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, alg_id};
use crate::crypto::sm2_ops::{
    pub_key_to_ecc_ref, ecc_ref_to_pub_key, ecc_ref_to_pri_key,
    sm2_enc, sm2_dec,
};

/// SDF_GenerateRandom — 生成随机数
pub fn sdf_generate_random(session_handle: u32, length: u32, random: &mut Vec<u8>) -> i32 {
    if length == 0 || length > 4096 {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        *random = generate_random(length as usize);
        log::debug!("SDF_GenerateRandom: {} 字节", length);
        SDR_OK
    })
}

/// SDF_GetPrivateKeyAccessRight — 获取私钥访问权限
pub fn sdf_get_private_key_access_right(
    session_handle: u32,
    key_index: u32,
    _password: &[u8],
) -> i32 {
    // Reason: Mock 场景不验证密码，直接授权
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        session.authorized_keys.insert(key_index);
        log::debug!("SDF_GetPrivateKeyAccessRight: index={}", key_index);
        SDR_OK
    })
}

/// SDF_ReleasePrivateKeyAccessRight — 释放私钥访问权限
pub fn sdf_release_private_key_access_right(session_handle: u32, key_index: u32) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        session.authorized_keys.remove(&key_index);
        log::debug!("SDF_ReleasePrivateKeyAccessRight: index={}", key_index);
        SDR_OK
    })
}

/// SDF_ExportSignPublicKey_ECC — 导出签名公钥
pub fn sdf_export_sign_public_key_ecc(
    session_handle: u32,
    key_index: u32,
    pub_key: &mut ECCrefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.key_store.get_sign_public_key(key_index) {
            Some(pk) => {
                *pub_key = pub_key_to_ecc_ref(&pk);
                log::debug!("SDF_ExportSignPublicKey_ECC: index={}", key_index);
                SDR_OK
            }
            None => {
                log::warn!("SDF_ExportSignPublicKey_ECC: 签名密钥索引{}不存在", key_index);
                SDR_KEYINDEX
            }
        }
    })
}

/// SDF_ExportEncPublicKey_ECC — 导出加密公钥
pub fn sdf_export_enc_public_key_ecc(
    session_handle: u32,
    key_index: u32,
    pub_key: &mut ECCrefPublicKey,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        match session.key_store.get_enc_public_key(key_index) {
            Some(pk) => {
                *pub_key = pub_key_to_ecc_ref(&pk);
                log::debug!("SDF_ExportEncPublicKey_ECC: index={}", key_index);
                SDR_OK
            }
            None => {
                log::warn!("SDF_ExportEncPublicKey_ECC: 加密密钥索引{}不存在", key_index);
                SDR_KEYINDEX
            }
        }
    })
}

/// SDF_GenerateKeyPair_ECC — 生成 ECC 密钥对
/// alg: 算法标识（SGD_SM2_1 签名 / SGD_SM2_3 加密）
/// bits: 密钥长度（SM2 固定256）
pub fn sdf_generate_key_pair_ecc(
    session_handle: u32,
    _alg: u32,
    _bits: u32,
    pub_key: &mut ECCrefPublicKey,
    pri_key: &mut ECCrefPrivateKey,
) -> i32 {
    with_session(session_handle, |res| {
        if let Err(e) = res { return e; }
        let (pri, pub_k) = sm2_keygen();
        *pub_key = pub_key_to_ecc_ref(&pub_k);
        pri_key.bits = 256;
        pri_key.K[32..64].copy_from_slice(&pri);
        log::debug!("SDF_GenerateKeyPair_ECC: 生成完毕");
        SDR_OK
    })
}

/// SDF_GenerateKeyWithKEK — 用 KEK 生成会话密钥（SM4，16字节随机密钥 + SM4-ECB 封装）
/// 返回：加密后的密钥密文 + 会话密钥句柄
pub fn sdf_generate_key_with_kek(
    session_handle: u32,
    bits: u32,
    kek_index: u32,
    cipher_key: &mut Vec<u8>,
    key_handle: &mut u32,
) -> i32 {
    if bits != 128 {
        return SDR_PARAMERR; // 仅支持 SM4 128位
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let kek = match session.key_store.get_kek(kek_index) {
            Some(k) => *k,
            None => {
                log::warn!("SDF_GenerateKeyWithKEK: KEK索引{}不存在", kek_index);
                return SDR_KEYINDEX;
            }
        };
        // 生成随机 SM4 会话密钥
        let session_key = generate_random(16);
        // 用 KEK 加密（SM4-ECB）
        let iv = [0u8; 16];
        let encrypted = match sm4_enc(&kek, &iv, alg_id::SGD_SM4_ECB, &session_key) {
            Ok(c) => c,
            Err(e) => { log::error!("KEK 加密失败: {}", e); return SDR_SYMOPERR; }
        };
        *cipher_key = encrypted;
        // 存储会话密钥
        let handle = session.key_store.store_session_key(
            KeyType::Symmetric,
            KeyData::Symmetric(session_key),
        );
        *key_handle = handle;
        log::debug!("SDF_GenerateKeyWithKEK: kek_index={}, handle=0x{:08X}", kek_index, handle);
        SDR_OK
    })
}

/// SDF_ImportKeyWithKEK — 用 KEK 导入会话密钥
pub fn sdf_import_key_with_kek(
    session_handle: u32,
    _alg: u32,
    kek_index: u32,
    cipher_key: &[u8],
    key_handle: &mut u32,
) -> i32 {
    if cipher_key.len() != 16 {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let kek = match session.key_store.get_kek(kek_index) {
            Some(k) => *k,
            None => return SDR_KEYINDEX,
        };
        let iv = [0u8; 16];
        let plain = match sm4_dec(&kek, &iv, alg_id::SGD_SM4_ECB, cipher_key) {
            Ok(p) => p,
            Err(_) => return SDR_SYMOPERR,
        };
        let handle = session.key_store.store_session_key(
            KeyType::Symmetric,
            KeyData::Symmetric(plain),
        );
        *key_handle = handle;
        log::debug!("SDF_ImportKeyWithKEK: handle=0x{:08X}", handle);
        SDR_OK
    })
}

/// SDF_GenerateKeyWithIPK_ECC — 用内部加密公钥封装会话密钥
pub fn sdf_generate_key_with_ipk_ecc(
    session_handle: u32,
    ipk_index: u32,
    bits: u32,
    cipher_key: &mut ECCCipher,
    key_handle: &mut u32,
) -> i32 {
    if bits != 128 {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let pub_k = match session.key_store.get_enc_public_key(ipk_index) {
            Some(pk) => pk,
            None => return SDR_KEYINDEX,
        };
        // 生成随机 SM4 会话密钥并用 SM2 加密
        let session_key = generate_random(16);
        match sm2_enc(&pub_k, &session_key) {
            Ok(c) => {
                *cipher_key = c;
                let handle = session.key_store.store_session_key(
                    KeyType::Symmetric,
                    KeyData::Symmetric(session_key),
                );
                *key_handle = handle;
                log::debug!("SDF_GenerateKeyWithIPK_ECC: ipk_index={}, handle=0x{:08X}", ipk_index, handle);
                SDR_OK
            }
            Err(e) => { log::error!("SM2 加密失败: {}", e); SDR_PKOPERR }
        }
    })
}

/// SDF_GenerateKeyWithEPK_ECC — 用外部公钥封装会话密钥
pub fn sdf_generate_key_with_epk_ecc(
    session_handle: u32,
    bits: u32,
    _alg: u32,
    pub_key: &ECCrefPublicKey,
    cipher_key: &mut ECCCipher,
    key_handle: &mut u32,
) -> i32 {
    if bits != 128 {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let pub_k = ecc_ref_to_pub_key(pub_key);
        let session_key = generate_random(16);
        match sm2_enc(&pub_k, &session_key) {
            Ok(c) => {
                *cipher_key = c;
                let handle = session.key_store.store_session_key(
                    KeyType::Symmetric,
                    KeyData::Symmetric(session_key),
                );
                *key_handle = handle;
                SDR_OK
            }
            Err(e) => { log::error!("SM2 加密失败: {}", e); SDR_PKOPERR }
        }
    })
}

/// SDF_ImportKeyWithISK_ECC — 用内部私钥解封装会话密钥
pub fn sdf_import_key_with_isk_ecc(
    session_handle: u32,
    isk_index: u32,
    cipher_key: &ECCCipher,
    key_handle: &mut u32,
) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        // 检查私钥访问权限
        if !session.authorized_keys.contains(&isk_index) {
            log::warn!("SDF_ImportKeyWithISK_ECC: 未授权的私钥访问 index={}", isk_index);
            return SDR_PARDENY;
        }
        let pri_k = match session.key_store.get_enc_key(isk_index) {
            Some((pri, _)) => *pri,
            None => return SDR_KEYINDEX,
        };
        match sm2_dec(&pri_k, cipher_key) {
            Some(plain) => {
                let handle = session.key_store.store_session_key(
                    KeyType::Symmetric,
                    KeyData::Symmetric(plain),
                );
                *key_handle = handle;
                log::debug!("SDF_ImportKeyWithISK_ECC: handle=0x{:08X}", handle);
                SDR_OK
            }
            None => { log::error!("SM2 解密失败"); SDR_PKOPERR }
        }
    })
}

/// SDF_DestroyKey — 销毁会话密钥
pub fn sdf_destroy_key(session_handle: u32, key_handle: u32) -> i32 {
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        if session.key_store.destroy_session_key(key_handle) {
            log::debug!("SDF_DestroyKey: handle=0x{:08X}", key_handle);
            SDR_OK
        } else {
            log::warn!("SDF_DestroyKey: 密钥句柄0x{:08X}不存在", key_handle);
            SDR_KEYNOTEXIST
        }
    })
}
