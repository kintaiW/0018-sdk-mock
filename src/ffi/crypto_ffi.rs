// 运算 FFI 导出（非对称、对称、哈希）
use std::os::raw::{c_int, c_void, c_uint, c_uchar};
use crate::error_code::SDR_PARAMERR;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature};
use crate::sdf_impl::{
    asymmetric::*,
    symmetric::*,
    hash::*,
};

// ──────────────── 非对称运算 ────────────────

/// SDF_ExternalSign_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalSign_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPrivateKey: *const ECCrefPrivateKey,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucPrivateKey.is_null() || pucData.is_null() || pucSignature.is_null() {
        return SDR_PARAMERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe {
        sdf_external_sign_ecc(handle, uiAlgID, &*pucPrivateKey, data, &mut *pucSignature)
    }
}

/// SDF_ExternalVerify_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalVerify_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *const ECCSignature,
) -> c_int {
    if pucPublicKey.is_null() || pucData.is_null() || pucSignature.is_null() {
        return SDR_PARAMERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe {
        sdf_external_verify_ecc(handle, uiAlgID, &*pucPublicKey, data, &*pucSignature)
    }
}

/// SDF_InternalSign_ECC
#[no_mangle]
pub extern "C" fn SDF_InternalSign_ECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: c_uint,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucData.is_null() || pucSignature.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe { sdf_internal_sign_ecc(handle, uiISKIndex, data, &mut *pucSignature) }
}

/// SDF_InternalVerify_ECC
#[no_mangle]
pub extern "C" fn SDF_InternalVerify_ECC(
    hSessionHandle: *mut c_void,
    uiIPKIndex: c_uint,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucSignature: *const ECCSignature,
) -> c_int {
    if pucData.is_null() || pucSignature.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe { sdf_internal_verify_ecc(handle, uiIPKIndex, data, &*pucSignature) }
}

/// SDF_ExternalEncrypt_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalEncrypt_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut ECCCipher,
) -> c_int {
    if pucPublicKey.is_null() || pucData.is_null() || pucEncData.is_null() {
        return SDR_PARAMERR;
    }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    unsafe {
        sdf_external_encrypt_ecc(handle, uiAlgID, &*pucPublicKey, data, &mut *pucEncData)
    }
}

/// SDF_ExternalDecrypt_ECC
#[no_mangle]
pub extern "C" fn SDF_ExternalDecrypt_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPrivateKey: *const ECCrefPrivateKey,
    pucEncData: *const ECCCipher,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucPrivateKey.is_null() || pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_PARAMERR;
    }
    let handle = hSessionHandle as usize as u32;
    let mut plaintext = Vec::new();
    let ret = unsafe {
        sdf_external_decrypt_ecc(handle, uiAlgID, &*pucPrivateKey, &*pucEncData, &mut plaintext)
    };
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), pucData, plaintext.len());
            *puiDataLength = plaintext.len() as c_uint;
        }
    }
    ret
}

// ──────────────── 对称运算 ────────────────

/// SDF_Encrypt
#[no_mangle]
pub extern "C" fn SDF_Encrypt(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucEncData: *mut c_uchar,
    puiEncDataLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || pucEncData.is_null() || puiEncDataLength.is_null() {
        return SDR_PARAMERR;
    }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut ct = Vec::new();
    let ret = sdf_encrypt(session, key, uiAlgID, &iv, data, &mut ct);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), pucEncData, ct.len());
            *puiEncDataLength = ct.len() as c_uint;
        }
    }
    ret
}

/// SDF_Decrypt
#[no_mangle]
pub extern "C" fn SDF_Decrypt(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
    pucEncData: *const c_uchar,
    uiEncDataLength: c_uint,
    pucData: *mut c_uchar,
    puiDataLength: *mut c_uint,
) -> c_int {
    if pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_PARAMERR;
    }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let ct = unsafe { std::slice::from_raw_parts(pucEncData, uiEncDataLength as usize) };
    let mut pt = Vec::new();
    let ret = sdf_decrypt(session, key, uiAlgID, &iv, ct, &mut pt);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), pucData, pt.len());
            *puiDataLength = pt.len() as c_uint;
        }
    }
    ret
}

/// SDF_CalculateMAC
#[no_mangle]
pub extern "C" fn SDF_CalculateMAC(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
    pucIV: *const c_uchar,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
    pucMAC: *mut c_uchar,
    puiMACLength: *mut c_uint,
) -> c_int {
    if pucData.is_null() || pucMAC.is_null() || puiMACLength.is_null() { return SDR_PARAMERR; }
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    let iv: [u8; 16] = if pucIV.is_null() {
        [0u8; 16]
    } else {
        unsafe { std::slice::from_raw_parts(pucIV, 16).try_into().unwrap() }
    };
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    let mut mac = [0u8; 16];
    let ret = sdf_calculate_mac(session, key, &iv, data, &mut mac);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), pucMAC, 16);
            *puiMACLength = 16;
        }
    }
    ret
}

// ──────────────── 哈希运算 ────────────────

/// SDF_HashInit
#[no_mangle]
pub extern "C" fn SDF_HashInit(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    pucPublicKey: *const ECCrefPublicKey,
    pucID: *const c_uchar,
    uiIDLength: c_uint,
) -> c_int {
    let handle = hSessionHandle as usize as u32;
    let pub_key = if pucPublicKey.is_null() {
        None
    } else {
        Some(unsafe { &*pucPublicKey })
    };
    let id = if pucID.is_null() || uiIDLength == 0 {
        &b"1234567812345678"[..]
    } else {
        unsafe { std::slice::from_raw_parts(pucID, uiIDLength as usize) }
    };
    sdf_hash_init(handle, uiAlgID, pub_key, id)
}

/// SDF_HashUpdate
#[no_mangle]
pub extern "C" fn SDF_HashUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
) -> c_int {
    if pucData.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    sdf_hash_update(handle, data)
}

/// SDF_HashFinal
#[no_mangle]
pub extern "C" fn SDF_HashFinal(
    hSessionHandle: *mut c_void,
    pucHash: *mut c_uchar,
    puiHashLength: *mut c_uint,
) -> c_int {
    if pucHash.is_null() || puiHashLength.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let mut hash = [0u8; 32];
    let ret = sdf_hash_final(handle, &mut hash);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), pucHash, 32);
            *puiHashLength = 32;
        }
    }
    ret
}

/// SDF_HMACInit
#[no_mangle]
pub extern "C" fn SDF_HMACInit(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: c_uint,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    sdf_hmac_init(session, key, uiAlgID)
}

/// SDF_HMACUpdate
#[no_mangle]
pub extern "C" fn SDF_HMACUpdate(
    hSessionHandle: *mut c_void,
    pucData: *const c_uchar,
    uiDataLength: c_uint,
) -> c_int {
    if pucData.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let data = unsafe { std::slice::from_raw_parts(pucData, uiDataLength as usize) };
    sdf_hmac_update(handle, data)
}

/// SDF_HMACFinal
#[no_mangle]
pub extern "C" fn SDF_HMACFinal(
    hSessionHandle: *mut c_void,
    pucMAC: *mut c_uchar,
    puiMACLength: *mut c_uint,
) -> c_int {
    if pucMAC.is_null() || puiMACLength.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let mut mac = [0u8; 32];
    let ret = sdf_hmac_final(handle, &mut mac);
    if ret == 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), pucMAC, 32);
            *puiMACLength = 32;
        }
    }
    ret
}
