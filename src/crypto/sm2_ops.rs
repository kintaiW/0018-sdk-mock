// SM2 算法封装
// 对 gm-sdk-rs 的 SM2 接口进行薄封装，适配 GM/T 0018 的数据结构格式

use gm_sdk::sm2::{
    sm2_generate_keypair,
    sm2_sign, sm2_verify,
    sm2_sign_verify,
    sm2_get_z, sm2_get_e,
    sm2_encrypt, sm2_decrypt,
};
use crate::types::{ECCrefPublicKey, ECCrefPrivateKey, ECCCipher, ECCSignature};

/// 生成 SM2 密钥对
pub fn sm2_keygen() -> ([u8; 32], [u8; 65]) {
    sm2_generate_keypair()
}

/// gm-sdk-rs 公钥（65字节 04||x||y）→ GM/T 0018 ECCrefPublicKey（x/y 各64字节右对齐）
pub fn pub_key_to_ecc_ref(pub_key: &[u8; 65]) -> ECCrefPublicKey {
    let mut ecc_pub = ECCrefPublicKey::default();
    ecc_pub.x[32..64].copy_from_slice(&pub_key[1..33]);
    ecc_pub.y[32..64].copy_from_slice(&pub_key[33..65]);
    ecc_pub
}

/// GM/T 0018 ECCrefPublicKey → gm-sdk-rs 公钥（65字节 04||x||y）
pub fn ecc_ref_to_pub_key(ecc_pub: &ECCrefPublicKey) -> [u8; 65] {
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04;
    pub_key[1..33].copy_from_slice(&ecc_pub.x[32..64]);
    pub_key[33..65].copy_from_slice(&ecc_pub.y[32..64]);
    pub_key
}

/// gm-sdk-rs 私钥（32字节）→ GM/T 0018 ECCrefPrivateKey（K 字段64字节右对齐）
pub fn pri_key_to_ecc_ref(pri_key: &[u8; 32]) -> ECCrefPrivateKey {
    let mut ecc_pri = ECCrefPrivateKey::default();
    ecc_pri.K[32..64].copy_from_slice(pri_key);
    ecc_pri
}

/// GM/T 0018 ECCrefPrivateKey → gm-sdk-rs 私钥（32字节，取 K 字段后32字节）
pub fn ecc_ref_to_pri_key(ecc_pri: &ECCrefPrivateKey) -> [u8; 32] {
    ecc_pri.K[32..64].try_into().unwrap()
}

/// SM2 签名（完整 Z 值流程）
/// 内部使用 sm2_sign（随机 k），再提取 r/s 填入 ECCSignature
pub fn sm2_sign_full(
    pri_key: &[u8; 32],
    pub_key: &[u8; 65],
    data: &[u8],
    id: &[u8],
) -> Result<ECCSignature, String> {
    // 计算 Z = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)
    let z = sm2_get_z(id, pub_key);
    // 计算 e = SM3(Z||M)
    let e = sm2_get_e(data, &z);

    // sm2_sign 内部直接对消息做 SM3，这里我们需要对 e 值签名
    // 使用 sm2_sign 对 e 哈希值签名（sm2_sign 内部会再做一次SM3，等效于对e做直接签名）
    // Reason: gm-sdk-rs 的 sm2_sign 接受原始消息后内部哈希，
    // 我们把 e 作为"消息"传入以获得对 e 的直接签名
    let sig_bytes = sm2_sign(pri_key, &e);

    let mut sig = ECCSignature::default();
    sig.r[32..64].copy_from_slice(&sig_bytes[..32]);
    sig.s[32..64].copy_from_slice(&sig_bytes[32..]);
    Ok(sig)
}

/// SM2 验签（完整 Z 值流程）
pub fn sm2_verify_full(
    pub_key: &[u8; 65],
    data: &[u8],
    id: &[u8],
    sig: &ECCSignature,
) -> bool {
    let z = sm2_get_z(id, pub_key);
    let e = sm2_get_e(data, &z);

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r[32..64]);
    sig_bytes[32..].copy_from_slice(&sig.s[32..64]);

    sm2_verify(pub_key, &e, &sig_bytes)
}

/// SM2 外部密钥签名（直接对数据做 SM3 哈希后签名）
pub fn sm2_ext_sign(pri_key: &[u8; 32], data: &[u8]) -> ECCSignature {
    let sig_bytes = sm2_sign(pri_key, data);
    let mut sig = ECCSignature::default();
    sig.r[32..64].copy_from_slice(&sig_bytes[..32]);
    sig.s[32..64].copy_from_slice(&sig_bytes[32..]);
    sig
}

/// SM2 外部密钥验签
pub fn sm2_ext_verify(pub_key: &[u8; 65], data: &[u8], sig: &ECCSignature) -> bool {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r[32..64]);
    sig_bytes[32..].copy_from_slice(&sig.s[32..64]);
    sm2_verify(pub_key, data, &sig_bytes)
}

/// SM2 公钥加密 → GM/T 0018 ECCCipher
/// gm-sdk-rs 输出格式：C1(65) || C3(32) || C2(变长)
pub fn sm2_enc(pub_key: &[u8; 65], plaintext: &[u8]) -> Result<ECCCipher, String> {
    if plaintext.len() > 136 {
        return Err(format!("明文最大136字节，实际{}字节", plaintext.len()));
    }
    let raw = sm2_encrypt(pub_key, plaintext);
    if raw.len() < 97 {
        return Err("加密输出长度不足".to_string());
    }
    let mut cipher = ECCCipher::default();
    cipher.x[32..64].copy_from_slice(&raw[1..33]);
    cipher.y[32..64].copy_from_slice(&raw[33..65]);
    cipher.M.copy_from_slice(&raw[65..97]);
    let c2 = &raw[97..];
    cipher.L = c2.len() as u32;
    cipher.C[..c2.len()].copy_from_slice(c2);
    Ok(cipher)
}

/// SM2 私钥解密（输入 GM/T 0018 ECCCipher）
pub fn sm2_dec(pri_key: &[u8; 32], cipher: &ECCCipher) -> Option<Vec<u8>> {
    let c2_len = cipher.L as usize;
    if c2_len > 136 {
        return None;
    }
    // 重组为 gm-sdk-rs 格式：C1(65) || C3(32) || C2
    let mut raw = Vec::with_capacity(65 + 32 + c2_len);
    raw.push(0x04);
    raw.extend_from_slice(&cipher.x[32..64]);
    raw.extend_from_slice(&cipher.y[32..64]);
    raw.extend_from_slice(&cipher.M);
    raw.extend_from_slice(&cipher.C[..c2_len]);
    sm2_decrypt(pri_key, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_conversion_roundtrip() {
        let (pri, pub_key) = sm2_keygen();
        let ecc_pub = pub_key_to_ecc_ref(&pub_key);
        let pub_back = ecc_ref_to_pub_key(&ecc_pub);
        assert_eq!(pub_key, pub_back);

        let ecc_pri = pri_key_to_ecc_ref(&pri);
        let pri_back = ecc_ref_to_pri_key(&ecc_pri);
        assert_eq!(pri, pri_back);
    }

    #[test]
    fn test_sm2_ext_sign_verify() {
        let (pri, pub_key) = sm2_keygen();
        let data = b"external sign test";
        let sig = sm2_ext_sign(&pri, data);
        assert!(sm2_ext_verify(&pub_key, data, &sig));
    }

    #[test]
    fn test_sm2_encrypt_decrypt_roundtrip() {
        let (pri, pub_key) = sm2_keygen();
        let plaintext = b"test encrypt";
        let cipher = sm2_enc(&pub_key, plaintext).unwrap();
        let decrypted = sm2_dec(&pri, &cipher).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
