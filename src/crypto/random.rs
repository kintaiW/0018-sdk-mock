// 随机数生成封装
use rand::RngCore;
use rand::rngs::OsRng;

/// 生成指定长度的密码学安全随机字节
pub fn generate_random(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}
