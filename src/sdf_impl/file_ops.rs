// 文件操作接口实现（Stub）
// GM/T 0018 §6.6 — 文件管理接口
// Mock 环境下不实现实际文件存储，全部返回 SDR_NOTSUPPORT

use crate::error_code::SDR_NOTSUPPORT;

/// SDF_CreateFile — 创建文件（Mock 不支持）
pub fn sdf_create_file(
    _session_handle: u32,
    _file_name: &[u8],
    _file_size: u32,
) -> i32 {
    log::warn!("SDF_CreateFile: Mock 不支持文件操作");
    SDR_NOTSUPPORT
}

/// SDF_WriteFile — 写入文件（Mock 不支持）
pub fn sdf_write_file(
    _session_handle: u32,
    _file_name: &[u8],
    _offset: u32,
    _data: &[u8],
) -> i32 {
    log::warn!("SDF_WriteFile: Mock 不支持文件操作");
    SDR_NOTSUPPORT
}

/// SDF_ReadFile — 读取文件（Mock 不支持）
pub fn sdf_read_file(
    _session_handle: u32,
    _file_name: &[u8],
    _offset: u32,
    _out_len: &mut u32,
) -> i32 {
    log::warn!("SDF_ReadFile: Mock 不支持文件操作");
    SDR_NOTSUPPORT
}

/// SDF_DeleteFile — 删除文件（Mock 不支持）
pub fn sdf_delete_file(
    _session_handle: u32,
    _file_name: &[u8],
) -> i32 {
    log::warn!("SDF_DeleteFile: Mock 不支持文件操作");
    SDR_NOTSUPPORT
}
