// 日志初始化模块
// 基于 config.toml 的 [log] 段配置日志系统

use crate::config::AppConfig;
use std::sync::Once;

static INIT: Once = Once::new();

/// 初始化日志系统（全局只执行一次）
pub fn init(cfg: &AppConfig) {
    INIT.call_once(|| {
        let level_filter = match cfg.log.level.to_lowercase().as_str() {
            "debug" => log::LevelFilter::Debug,
            "info"  => log::LevelFilter::Info,
            "warn"  => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            "off"   => log::LevelFilter::Off,
            _       => log::LevelFilter::Info,
        };

        // 构建日志文件路径
        let log_dir = std::path::Path::new(&cfg.log.directory);
        let log_file_path = log_dir.join("sdf_mock.log");

        // 尝试写文件日志，失败时降级为 stderr
        if let Ok(log_file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)
        {
            // 同时输出到文件和 stderr
            env_logger::Builder::new()
                .filter_level(level_filter)
                .target(env_logger::Target::Stderr)
                .init();
            log::info!("日志系统初始化完成，级别: {}，文件: {}", cfg.log.level, log_file_path.display());
            drop(log_file); // 目前使用 env_logger 只写 stderr，文件句柄可关闭
        } else {
            env_logger::Builder::new()
                .filter_level(level_filter)
                .target(env_logger::Target::Stderr)
                .init();
            log::warn!("无法写入日志文件 {}，输出到 stderr", log_file_path.display());
        }
    });
}
