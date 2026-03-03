// 密钥管理 FFI 导出
use std::os::raw::{c_int, c_void, c_uint};
use crate::error_code::SDR_PARAMERR;
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher};
use crate::sdf_impl::key_manage::*;
use crate::ffi::helpers::{ptr_to_slice, write_output};

/// SDF_GenerateRandom
#[no_mangle]
pub extern "C" fn SDF_GenerateRandom(
    hSessionHandle: *mut c_void,
    uiLength: c_uint,
    pucRandom: *mut u8,
) -> c_int {
    if pucRandom.is_null() || uiLength == 0 {
        return SDR_PARAMERR;
    }
    let handle = hSessionHandle as usize as u32;
    let mut random = Vec::new();
    let ret = sdf_generate_random(handle, uiLength, &mut random);
    if ret == 0 {
        unsafe { std::ptr::copy_nonoverlapping(random.as_ptr(), pucRandom, random.len()); }
    }
    ret
}

/// SDF_GetPrivateKeyAccessRight
#[no_mangle]
pub extern "C" fn SDF_GetPrivateKeyAccessRight(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPassword: *const u8,
    uiPwdLength: c_uint,
) -> c_int {
    let handle = hSessionHandle as usize as u32;
    let pwd = if pucPassword.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pucPassword, uiPwdLength as usize) }
    };
    sdf_get_private_key_access_right(handle, uiKeyIndex, pwd)
}

/// SDF_ReleasePrivateKeyAccessRight
#[no_mangle]
pub extern "C" fn SDF_ReleasePrivateKeyAccessRight(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
) -> c_int {
    let handle = hSessionHandle as usize as u32;
    sdf_release_private_key_access_right(handle, uiKeyIndex)
}

/// SDF_ExportSignPublicKey_ECC
#[no_mangle]
pub extern "C" fn SDF_ExportSignPublicKey_ECC(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_export_sign_public_key_ecc(handle, uiKeyIndex, &mut *pucPublicKey) }
}

/// SDF_ExportEncPublicKey_ECC
#[no_mangle]
pub extern "C" fn SDF_ExportEncPublicKey_ECC(
    hSessionHandle: *mut c_void,
    uiKeyIndex: c_uint,
    pucPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe { sdf_export_enc_public_key_ecc(handle, uiKeyIndex, &mut *pucPublicKey) }
}

/// SDF_GenerateKeyPair_ECC
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyPair_ECC(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    uiKeyBits: c_uint,
    pucPublicKey: *mut ECCrefPublicKey,
    pucPrivateKey: *mut ECCrefPrivateKey,
) -> c_int {
    if pucPublicKey.is_null() || pucPrivateKey.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    unsafe {
        sdf_generate_key_pair_ecc(handle, uiAlgID, uiKeyBits, &mut *pucPublicKey, &mut *pucPrivateKey)
    }
}

/// SDF_GenerateKeyWithKEK
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyWithKEK(
    hSessionHandle: *mut c_void,
    uiLength: c_uint,
    uiAlgID: c_uint,  // 实际对应 KEK 索引
    uiKEKIndex: c_uint,
    pucKey: *mut u8,
    puiKeyLength: *mut c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || puiKeyLength.is_null() || phKeyHandle.is_null() {
        return SDR_PARAMERR;
    }
    let handle = hSessionHandle as usize as u32;
    let mut cipher_key = Vec::new();
    let mut key_handle: u32 = 0;
    let ret = sdf_generate_key_with_kek(handle, uiLength, uiKEKIndex, &mut cipher_key, &mut key_handle);
    if ret == 0 {
        unsafe {
            let cap = *puiKeyLength as usize;
            if cipher_key.len() <= cap {
                std::ptr::copy_nonoverlapping(cipher_key.as_ptr(), pucKey, cipher_key.len());
                *puiKeyLength = cipher_key.len() as c_uint;
            }
            *phKeyHandle = key_handle as usize as *mut c_void;
        }
    }
    ret
}

/// SDF_ImportKeyWithKEK
#[no_mangle]
pub extern "C" fn SDF_ImportKeyWithKEK(
    hSessionHandle: *mut c_void,
    uiAlgID: c_uint,
    uiKEKIndex: c_uint,
    pucKey: *const u8,
    uiKeyLength: c_uint,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let key_bytes = unsafe { std::slice::from_raw_parts(pucKey, uiKeyLength as usize) };
    let mut key_handle: u32 = 0;
    let ret = sdf_import_key_with_kek(handle, uiAlgID, uiKEKIndex, key_bytes, &mut key_handle);
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}

/// SDF_DestroyKey
#[no_mangle]
pub extern "C" fn SDF_DestroyKey(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
) -> c_int {
    let session = hSessionHandle as usize as u32;
    let key = hKeyHandle as usize as u32;
    sdf_destroy_key(session, key)
}

/// SDF_GenerateKeyWithIPK_ECC
#[no_mangle]
pub extern "C" fn SDF_GenerateKeyWithIPK_ECC(
    hSessionHandle: *mut c_void,
    uiIPKIndex: c_uint,
    uiKeyBits: c_uint,
    pucKey: *mut ECCCipher,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let mut cipher = ECCCipher::default();
    let mut key_handle: u32 = 0;
    let ret = sdf_generate_key_with_ipk_ecc(handle, uiIPKIndex, uiKeyBits, &mut cipher, &mut key_handle);
    if ret == 0 {
        unsafe {
            *pucKey = cipher;
            *phKeyHandle = key_handle as usize as *mut c_void;
        }
    }
    ret
}

/// SDF_ImportKeyWithISK_ECC
#[no_mangle]
pub extern "C" fn SDF_ImportKeyWithISK_ECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: c_uint,
    pucKey: *const ECCCipher,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if pucKey.is_null() || phKeyHandle.is_null() { return SDR_PARAMERR; }
    let handle = hSessionHandle as usize as u32;
    let mut key_handle: u32 = 0;
    let ret = unsafe { sdf_import_key_with_isk_ecc(handle, uiISKIndex, &*pucKey, &mut key_handle) };
    if ret == 0 {
        unsafe { *phKeyHandle = key_handle as usize as *mut c_void; }
    }
    ret
}
