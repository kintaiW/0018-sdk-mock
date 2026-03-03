// GM/T 0018 Mock SDK 集成测试
// 通过库公开接口（sdf_impl 层）进行端到端测试
// 不依赖 mock_keys.toml，所有密钥均在测试中临时生成

use std::sync::Mutex;
use sdf_mock::error_code::*;
use sdf_mock::sdf_impl::{
    device::{sdf_open_device, sdf_close_device, sdf_open_session, sdf_close_session, sdf_get_device_info},
    key_manage::{sdf_generate_random, sdf_generate_key_pair_ecc, sdf_destroy_key},
    asymmetric::{sdf_external_sign_ecc, sdf_external_verify_ecc,
                 sdf_external_encrypt_ecc, sdf_external_decrypt_ecc},
    symmetric::{sdf_encrypt, sdf_decrypt, sdf_calculate_mac},
    hash::{sdf_hash_init, sdf_hash_update, sdf_hash_final,
           sdf_hmac_init, sdf_hmac_update, sdf_hmac_final},
};
use sdf_mock::types::{DEVICEINFO, ECCrefPublicKey, ECCrefPrivateKey, ECCSignature, alg_id};
use sdf_mock::key_mgr::{KeyType, KeyData};
use sdf_mock::sdf_impl::device::with_session;

// 全局序列化锁（设备是单例）
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup() -> u32 {
    // 重置设备状态
    let _ = sdf_close_device();
    assert_eq!(sdf_open_device(), SDR_OK);
    let mut handle = 0u32;
    assert_eq!(sdf_open_session(&mut handle), SDR_OK);
    assert_ne!(handle, 0);
    handle
}

fn teardown(session: u32) {
    let _ = sdf_close_session(session);
    let _ = sdf_close_device();
}

// ── 设备基础 ───────────────────────────────────────────────────

#[test]
fn test_get_device_info() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut info = DEVICEINFO::default();
    assert_eq!(sdf_get_device_info(session, &mut info), SDR_OK);
    // Mock 设备名称应非空
    assert!(info.DeviceName.iter().any(|&b| b != 0));

    teardown(session);
}

#[test]
fn test_generate_random() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut buf = Vec::new();
    assert_eq!(sdf_generate_random(session, 32, &mut buf), SDR_OK);
    assert_eq!(buf.len(), 32);
    // 随机数不应全为零（概率极低）
    assert!(buf.iter().any(|&b| b != 0));

    teardown(session);
}

#[test]
fn test_generate_random_invalid() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut buf = Vec::new();
    // 长度为0 → 参数错误
    assert_eq!(sdf_generate_random(session, 0, &mut buf), SDR_PARAMERR);
    // 长度过大
    assert_eq!(sdf_generate_random(session, 5000, &mut buf), SDR_PARAMERR);

    teardown(session);
}

// ── SM2 外部签名/验签 ──────────────────────────────────────────

#[test]
fn test_sm2_external_sign_verify() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = ECCrefPublicKey::default();
    let mut pri_key = ECCrefPrivateKey::default();
    assert_eq!(
        sdf_generate_key_pair_ecc(session, alg_id::SGD_SM2_1, 256, &mut pub_key, &mut pri_key),
        SDR_OK
    );

    // 待签名数据（32字节哈希值）
    let data = [0xABu8; 32];
    let mut sig = ECCSignature::default();
    assert_eq!(
        sdf_external_sign_ecc(session, alg_id::SGD_SM2_1, &pri_key, &data, &mut sig),
        SDR_OK
    );

    // 验签成功
    assert_eq!(
        sdf_external_verify_ecc(session, alg_id::SGD_SM2_1, &pub_key, &data, &sig),
        SDR_OK
    );

    teardown(session);
}

#[test]
fn test_sm2_verify_wrong_data_fails() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = ECCrefPublicKey::default();
    let mut pri_key = ECCrefPrivateKey::default();
    assert_eq!(
        sdf_generate_key_pair_ecc(session, alg_id::SGD_SM2_1, 256, &mut pub_key, &mut pri_key),
        SDR_OK
    );

    let data = [0x11u8; 32];
    let mut sig = ECCSignature::default();
    assert_eq!(
        sdf_external_sign_ecc(session, alg_id::SGD_SM2_1, &pri_key, &data, &mut sig),
        SDR_OK
    );

    // 用不同数据验签 → 失败
    let wrong_data = [0x22u8; 32];
    assert_eq!(
        sdf_external_verify_ecc(session, alg_id::SGD_SM2_1, &pub_key, &wrong_data, &sig),
        SDR_VERIFYERR
    );

    teardown(session);
}

// ── SM2 外部加密/解密 ──────────────────────────────────────────

#[test]
fn test_sm2_external_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let mut pub_key = ECCrefPublicKey::default();
    let mut pri_key = ECCrefPrivateKey::default();
    assert_eq!(
        sdf_generate_key_pair_ecc(session, alg_id::SGD_SM2_3, 256, &mut pub_key, &mut pri_key),
        SDR_OK
    );

    let plaintext = b"integration test plaintext";
    let mut cipher = sdf_mock::types::ECCCipher::default();
    assert_eq!(
        sdf_external_encrypt_ecc(session, alg_id::SGD_SM2_3, &pub_key, plaintext, &mut cipher),
        SDR_OK
    );
    assert_eq!(cipher.L as usize, plaintext.len());

    let mut recovered = Vec::new();
    assert_eq!(
        sdf_external_decrypt_ecc(session, alg_id::SGD_SM2_3, &pri_key, &cipher, &mut recovered),
        SDR_OK
    );
    assert_eq!(recovered, plaintext);

    teardown(session);
}

// ── SM3 哈希 ────────────────────────────────────────────────────

#[test]
fn test_sm3_hash() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let data = b"abc";
    assert_eq!(sdf_hash_init(session, alg_id::SGD_SM3, None, b""), SDR_OK);
    assert_eq!(sdf_hash_update(session, data), SDR_OK);

    let mut hash = [0u8; 32];
    assert_eq!(sdf_hash_final(session, &mut hash), SDR_OK);

    // SM3("abc") 已知值
    let expected = hex::decode("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        .unwrap();
    assert_eq!(&hash, expected.as_slice());

    teardown(session);
}

#[test]
fn test_sm3_hash_incremental() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    // 分块 update 与一次性 update 结果应相同
    assert_eq!(sdf_hash_init(session, alg_id::SGD_SM3, None, b""), SDR_OK);
    assert_eq!(sdf_hash_update(session, b"hel"), SDR_OK);
    assert_eq!(sdf_hash_update(session, b"lo"), SDR_OK);
    let mut hash1 = [0u8; 32];
    assert_eq!(sdf_hash_final(session, &mut hash1), SDR_OK);

    // 重新 Init，一次性 update
    assert_eq!(sdf_hash_init(session, alg_id::SGD_SM3, None, b""), SDR_OK);
    assert_eq!(sdf_hash_update(session, b"hello"), SDR_OK);
    let mut hash2 = [0u8; 32];
    assert_eq!(sdf_hash_final(session, &mut hash2), SDR_OK);

    assert_eq!(hash1, hash2);

    teardown(session);
}

// ── SM4-CBC 加密/解密 ─────────────────────────────────────────

fn make_sym_key(session: u32) -> u32 {
    // 直接向会话注入一个已知 SM4 密钥（绕过 KEK，仅用于测试）
    let key_data = KeyData::Symmetric(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ]);
    let mut handle = 0u32;
    with_session(session, |res| {
        let s = res.unwrap();
        handle = s.key_store.store_session_key(KeyType::Symmetric, key_data.clone());
        0i32
    });
    handle
}

#[test]
fn test_sm4_cbc_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0u8; 16];
    let plaintext = b"1234567890ABCDEF"; // 16 字节
    let mut ciphertext = Vec::new();
    assert_eq!(
        sdf_encrypt(session, key_handle, alg_id::SGD_SM4_CBC, &iv, plaintext, &mut ciphertext),
        SDR_OK
    );
    assert_eq!(ciphertext.len(), 16);

    let mut recovered = Vec::new();
    assert_eq!(
        sdf_decrypt(session, key_handle, alg_id::SGD_SM4_CBC, &iv, &ciphertext, &mut recovered),
        SDR_OK
    );
    assert_eq!(&recovered, plaintext);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

#[test]
fn test_sm4_ecb_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0u8; 16];
    let plaintext = b"ABCDEFGHIJKLMNOP"; // 16 字节
    let mut ct = Vec::new();
    assert_eq!(
        sdf_encrypt(session, key_handle, alg_id::SGD_SM4_ECB, &iv, plaintext, &mut ct),
        SDR_OK
    );

    let mut pt = Vec::new();
    assert_eq!(
        sdf_decrypt(session, key_handle, alg_id::SGD_SM4_ECB, &iv, &ct, &mut pt),
        SDR_OK
    );
    assert_eq!(&pt, plaintext);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

#[test]
fn test_sm4_ctr_encrypt_decrypt() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0x01u8; 16];
    let plaintext = b"CTR mode test!!"; // 任意长度
    let mut ct = Vec::new();
    assert_eq!(
        sdf_encrypt(session, key_handle, alg_id::SGD_SM4_CTR, &iv, plaintext, &mut ct),
        SDR_OK
    );
    assert_eq!(ct.len(), plaintext.len());

    let mut pt = Vec::new();
    assert_eq!(
        sdf_decrypt(session, key_handle, alg_id::SGD_SM4_CTR, &iv, &ct, &mut pt),
        SDR_OK
    );
    assert_eq!(&pt, plaintext);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

// ── CBC-MAC ───────────────────────────────────────────────────

#[test]
fn test_calculate_mac() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    let iv = [0u8; 16];
    let data = [0xFFu8; 32]; // 32 字节
    let mut mac = [0u8; 16];
    assert_eq!(sdf_calculate_mac(session, key_handle, &iv, &data, &mut mac), SDR_OK);
    // MAC 不应全零
    assert!(mac.iter().any(|&b| b != 0));

    // 相同输入，相同 MAC
    let mut mac2 = [0u8; 16];
    assert_eq!(sdf_calculate_mac(session, key_handle, &iv, &data, &mut mac2), SDR_OK);
    assert_eq!(mac, mac2);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

// ── HMAC-SM3 ─────────────────────────────────────────────────

#[test]
fn test_hmac_sm3() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    assert_eq!(sdf_hmac_init(session, key_handle, alg_id::SGD_SM3), SDR_OK);
    assert_eq!(sdf_hmac_update(session, b"hello"), SDR_OK);
    assert_eq!(sdf_hmac_update(session, b" world"), SDR_OK);

    let mut mac = [0u8; 32];
    assert_eq!(sdf_hmac_final(session, &mut mac), SDR_OK);
    assert!(mac.iter().any(|&b| b != 0));

    // 相同数据，相同 HMAC
    assert_eq!(sdf_hmac_init(session, key_handle, alg_id::SGD_SM3), SDR_OK);
    assert_eq!(sdf_hmac_update(session, b"hello world"), SDR_OK);
    let mut mac2 = [0u8; 32];
    assert_eq!(sdf_hmac_final(session, &mut mac2), SDR_OK);
    assert_eq!(mac, mac2);

    let _ = sdf_destroy_key(session, key_handle);
    teardown(session);
}

// ── 密钥句柄生命周期 ─────────────────────────────────────────

#[test]
fn test_destroy_key() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();
    let key_handle = make_sym_key(session);

    // 正常销毁
    assert_eq!(sdf_destroy_key(session, key_handle), SDR_OK);
    // 重复销毁 → 密钥不存在
    assert_eq!(sdf_destroy_key(session, key_handle), SDR_KEYNOTEXIST);

    teardown(session);
}

// ── 错误路径 ─────────────────────────────────────────────────

#[test]
fn test_ops_without_open_device() {
    let _lock = TEST_MUTEX.lock().unwrap();
    // 确保设备未打开
    let _ = sdf_close_device();

    let mut handle = 0u32;
    // 设备未开，OpenSession 应失败
    assert_eq!(sdf_open_session(&mut handle), SDR_OPENDEVICE);
    assert_eq!(handle, 0);
}

#[test]
fn test_invalid_session_handle() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let session = setup();

    let bad_handle = 0xDEAD_BEEFu32;
    // 无效会话句柄
    let mut buf = Vec::new();
    assert_eq!(sdf_generate_random(bad_handle, 16, &mut buf), SDR_INVALIDHANDLE);

    teardown(session);
}
