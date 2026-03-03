// 设备管理接口实现
// SDF_OpenDevice / SDF_CloseDevice / SDF_OpenSession / SDF_CloseSession / SDF_GetDeviceInfo

use std::sync::{Mutex, OnceLock};
use crate::config::{AppConfig, MockConfig};
use crate::error_code::*;
use crate::key_mgr::DeviceContext;
use crate::types::DEVICEINFO;
use crate::logging;
use std::path::Path;

/// 全局设备上下文（单例）
/// Reason: SDF 标准中设备是全局唯一资源，用 OnceLock+Mutex 保证初始化一次且线程安全
static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>> = OnceLock::new();

fn device_lock() -> &'static Mutex<Option<DeviceContext>> {
    DEVICE_CTX.get_or_init(|| Mutex::new(None))
}

/// 按优先级查找 config.toml：可执行文件目录 → 当前工作目录
/// Reason: 动态库加载时 CWD 是调用方目录，不一定与配置文件同级
fn find_config_toml() -> Option<std::path::PathBuf> {
    // 1. 可执行文件所在目录
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.toml");
            if p.exists() { return Some(p); }
        }
    }
    // 2. 当前工作目录
    let p = Path::new("config.toml").to_path_buf();
    if p.exists() { return Some(p); }
    None
}

/// SDF_OpenDevice — 打开设备（初始化 Mock 上下文）
/// 返回：SDR_OK 或错误码
pub fn sdf_open_device() -> i32 {
    // 1. 加载 app config（日志配置）；config.toml 不存在则报错并终止
    let config_path = match find_config_toml() {
        Some(p) => p,
        None => {
            eprintln!("SDF_OpenDevice 失败: config.toml 不存在（已搜索可执行文件目录和当前目录）");
            return SDR_CONFIGERR;
        }
    };
    let app_cfg = match AppConfig::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("SDF_OpenDevice 失败: {}", e);
            return SDR_CONFIGERR;
        }
    };
    logging::init(&app_cfg);

    log::info!("SDF_OpenDevice: 初始化 Mock 设备");

    // 2. 加载 mock 密钥配置
    let mock_cfg = MockConfig::load_from_env_or_default();

    // 3. 初始化全局设备上下文
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    if guard.is_some() {
        log::warn!("SDF_OpenDevice: 设备已打开，忽略重复调用");
        return SDR_OK;
    }
    *guard = Some(DeviceContext::new(mock_cfg));
    log::info!("SDF_OpenDevice: Mock 设备打开成功");
    SDR_OK
}

/// SDF_CloseDevice — 关闭设备
pub fn sdf_close_device() -> i32 {
    log::info!("SDF_CloseDevice");
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    if guard.is_none() {
        log::warn!("SDF_CloseDevice: 设备未打开");
        return SDR_OPENDEVICE;
    }
    *guard = None;
    SDR_OK
}

/// SDF_OpenSession — 打开会话
/// 返回会话句柄（通过 out_handle 输出），成功返回 SDR_OK
pub fn sdf_open_session(out_handle: &mut u32) -> i32 {
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => {
            log::error!("SDF_OpenSession: 设备未打开");
            return SDR_OPENDEVICE;
        }
    };
    let handle = ctx.open_session();
    *out_handle = handle;
    log::debug!("SDF_OpenSession: handle=0x{:08X}", handle);
    SDR_OK
}

/// SDF_CloseSession — 关闭会话
pub fn sdf_close_session(session_handle: u32) -> i32 {
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => return SDR_OPENDEVICE,
    };
    if ctx.close_session(session_handle) {
        log::debug!("SDF_CloseSession: handle=0x{:08X}", session_handle);
        SDR_OK
    } else {
        log::warn!("SDF_CloseSession: 无效会话句柄 0x{:08X}", session_handle);
        SDR_INVALIDHANDLE
    }
}

/// SDF_GetDeviceInfo — 获取设备信息
pub fn sdf_get_device_info(session_handle: u32, info: &mut DEVICEINFO) -> i32 {
    let guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return SDR_UNKNOWERR,
    };
    let ctx = match guard.as_ref() {
        Some(c) => c,
        None => return SDR_OPENDEVICE,
    };
    if ctx.get_session(session_handle).is_none() {
        return SDR_INVALIDHANDLE;
    }
    let cfg = &ctx.mock_cfg.device;
    // 填充设备信息
    *info = DEVICEINFO::default();
    let mfr = cfg.manufacturer.as_bytes();
    let copy_len = mfr.len().min(40);
    info.IssuerName[..copy_len].copy_from_slice(&mfr[..copy_len]);

    let name = cfg.device_name.as_bytes();
    let copy_len = name.len().min(16);
    info.DeviceName[..copy_len].copy_from_slice(&name[..copy_len]);

    let serial = cfg.device_serial.as_bytes();
    let copy_len = serial.len().min(16);
    info.DeviceSerial[..copy_len].copy_from_slice(&serial[..copy_len]);

    log::debug!("SDF_GetDeviceInfo: 返回设备信息");
    SDR_OK
}

/// 辅助：在已持有 device_lock 的情况下，对会话执行操作
/// 供其他模块调用，避免多次加锁
pub fn with_session<F, R>(session_handle: u32, f: F) -> R
where
    F: FnOnce(Result<&mut crate::key_mgr::SessionContext, i32>) -> R,
{
    let mut guard = match device_lock().lock() {
        Ok(g) => g,
        Err(_) => return f(Err(SDR_UNKNOWERR)),
    };
    let ctx = match guard.as_mut() {
        Some(c) => c,
        None => return f(Err(SDR_OPENDEVICE)),
    };
    match ctx.get_session_mut(session_handle) {
        Some(s) => f(Ok(s)),
        None => f(Err(SDR_INVALIDHANDLE)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Reason: 设备上下文是全局单例，多个测试并发运行时会相互干扰，需串行化
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn cleanup() {
        if let Ok(mut g) = device_lock().lock() {
            *g = None;
        }
    }

    #[test]
    fn test_open_close_device() {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup();
        assert_eq!(sdf_open_device(), SDR_OK);
        assert_eq!(sdf_close_device(), SDR_OK);
        cleanup();
    }

    #[test]
    fn test_open_session() {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup();
        assert_eq!(sdf_open_device(), SDR_OK);
        let mut handle = 0u32;
        assert_eq!(sdf_open_session(&mut handle), SDR_OK);
        assert_ne!(handle, 0);
        assert_eq!(sdf_close_session(handle), SDR_OK);
        assert_eq!(sdf_close_device(), SDR_OK);
        cleanup();
    }

    #[test]
    fn test_invalid_session() {
        let _guard = TEST_MUTEX.lock().unwrap();
        cleanup();
        assert_eq!(sdf_open_device(), SDR_OK);
        assert_eq!(sdf_close_session(0xDEADBEEF), SDR_INVALIDHANDLE);
        assert_eq!(sdf_close_device(), SDR_OK);
        cleanup();
    }

    /// config.toml 不存在时，AppConfig::load 返回 Err，sdf_open_device 返回 SDR_CONFIGERR
    #[test]
    fn test_open_device_missing_config() {
        // 直接测试 AppConfig::load 的错误路径，不影响全局设备状态
        let result = AppConfig::load(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("config.toml 不存在"), "错误信息: {}", msg);
    }
}
