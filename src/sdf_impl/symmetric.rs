// 对称运算接口实现
// SDF_Encrypt / SDF_Decrypt / SDF_CalculateMAC / SDF_AuthEnc / SDF_AuthDec

use crate::error_code::*;
use crate::sdf_impl::device::with_session;
use crate::key_mgr::KeyData;
use crate::crypto::sm4_ops::{sm4_encrypt, sm4_decrypt, sm4_cbc_mac, sm4_gcm_encrypt, sm4_gcm_decrypt, sm4_ccm_encrypt, sm4_ccm_decrypt};
use crate::types::alg_id;

/// 从会话密钥句柄提取 SM4 密钥（16字节）
fn extract_sym_key(key_data: &KeyData) -> Option<[u8; 16]> {
    if let KeyData::Symmetric(v) = key_data {
        if v.len() == 16 {
            return Some(v.as_slice().try_into().unwrap());
        }
    }
    None
}

/// SDF_Encrypt — 对称加密
/// key_handle: 会话密钥句柄
/// alg: 算法标识（SGD_SM4_ECB/CBC/CFB/OFB/CTR）
/// iv: 初始向量（16字节，ECB 忽略）
/// plaintext: 明文
pub fn sdf_encrypt(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    iv: &[u8; 16],
    plaintext: &[u8],
    ciphertext: &mut Vec<u8>,
) -> i32 {
    if plaintext.is_empty() {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match sm4_encrypt(&key, iv, alg, plaintext) {
            Ok(ct) => {
                *ciphertext = ct;
                log::debug!("SDF_Encrypt: alg=0x{:08X}, in={}, out={}", alg, plaintext.len(), ciphertext.len());
                SDR_OK
            }
            Err(e) => { log::error!("SDF_Encrypt 失败: {}", e); SDR_SYMOPERR }
        }
    })
}

/// SDF_Decrypt — 对称解密
pub fn sdf_decrypt(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    iv: &[u8; 16],
    ciphertext: &[u8],
    plaintext: &mut Vec<u8>,
) -> i32 {
    if ciphertext.is_empty() {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match sm4_decrypt(&key, iv, alg, ciphertext) {
            Ok(pt) => {
                *plaintext = pt;
                log::debug!("SDF_Decrypt: alg=0x{:08X}, in={}, out={}", alg, ciphertext.len(), plaintext.len());
                SDR_OK
            }
            Err(e) => { log::error!("SDF_Decrypt 失败: {}", e); SDR_SYMOPERR }
        }
    })
}

/// SDF_CalculateMAC — 计算 SM4-CBC-MAC
pub fn sdf_calculate_mac(
    session_handle: u32,
    key_handle: u32,
    iv: &[u8; 16],
    data: &[u8],
    mac: &mut [u8; 16],
) -> i32 {
    if data.is_empty() || data.len() % 16 != 0 {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match sm4_cbc_mac(&key, iv, data) {
            Ok(m) => {
                *mac = m;
                log::debug!("SDF_CalculateMAC: data_len={}", data.len());
                SDR_OK
            }
            Err(e) => { log::error!("MAC 计算失败: {}", e); SDR_SYMOPERR }
        }
    })
}

/// SDF_AuthEnc — 可鉴别加密（GCM/CCM）
/// nonce: 12字节随机数
/// aad: 附加认证数据
/// alg: SGD_SM4_GCM 或 SGD_SM4_CCM
/// 返回：密文 + 认证标签（GCM 固定16字节标签，CCM 标签附在密文后）
pub fn sdf_auth_enc(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut Vec<u8>,
    tag: &mut [u8; 16],
) -> i32 {
    if plaintext.is_empty() {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match alg {
            alg_id::SGD_SM4_GCM => {
                let (ct, t) = sm4_gcm_encrypt(&key, nonce, aad, plaintext);
                *ciphertext = ct;
                *tag = t;
                SDR_OK
            }
            alg_id::SGD_SM4_CCM => {
                // CCM 标签长度固定16字节
                let ct = sm4_ccm_encrypt(&key, nonce, aad, plaintext, 16);
                let ct_len = ct.len() - 16;
                *tag = ct[ct_len..].try_into().unwrap();
                *ciphertext = ct[..ct_len].to_vec();
                SDR_OK
            }
            _ => SDR_ALGNOTSUPPORT,
        }
    })
}

/// SDF_AuthDec — 可鉴别解密（GCM/CCM）
pub fn sdf_auth_dec(
    session_handle: u32,
    key_handle: u32,
    alg: u32,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut Vec<u8>,
) -> i32 {
    if ciphertext.is_empty() {
        return SDR_PARAMERR;
    }
    with_session(session_handle, |res| {
        let session = match res { Ok(s) => s, Err(e) => return e };
        let entry = match session.key_store.get_session_key(key_handle) {
            Some(e) => e,
            None => return SDR_KEYNOTEXIST,
        };
        let key = match extract_sym_key(&entry.data) {
            Some(k) => k,
            None => return SDR_KEYTYPEERR,
        };
        match alg {
            alg_id::SGD_SM4_GCM => {
                match sm4_gcm_decrypt(&key, nonce, aad, ciphertext, tag) {
                    Ok(pt) => { *plaintext = pt; SDR_OK }
                    Err(e) => { log::warn!("GCM 解密认证失败: {}", e); SDR_VERIFYERR }
                }
            }
            alg_id::SGD_SM4_CCM => {
                // 重组密文+标签
                let mut ct_with_tag = ciphertext.to_vec();
                ct_with_tag.extend_from_slice(tag);
                match sm4_ccm_decrypt(&key, nonce, aad, &ct_with_tag, 16) {
                    Ok(pt) => { *plaintext = pt; SDR_OK }
                    Err(e) => { log::warn!("CCM 解密认证失败: {}", e); SDR_VERIFYERR }
                }
            }
            _ => SDR_ALGNOTSUPPORT,
        }
    })
}
