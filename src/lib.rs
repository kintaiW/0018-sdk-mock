// GM/T 0018 密码设备接口模拟 SDK
// 库入口：声明所有模块并引入 FFI 导出

pub mod error_code;
pub mod types;
pub mod config;
pub mod logging;
pub mod key_mgr;
pub mod crypto;
pub mod sdf_impl;
pub mod ffi;

// 引入 FFI 导出（使 #[no_mangle] 函数被编译进动态库）
use ffi::device_ffi::*;
use ffi::key_ffi::*;
use ffi::crypto_ffi::*;
