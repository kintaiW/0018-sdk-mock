// config.toml 解析（仅日志段生效）
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    /// 日志级别：debug, info, warn, error, off
    pub level: String,
    /// 日志输出目录
    pub directory: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            directory: "./".to_string(),
        }
    }
}

/// config.toml 的顶层结构（只提取 log 段，其余段忽略）
#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub log: LogConfig,
}

impl AppConfig {
    /// 从文件路径加载配置。
    /// 文件不存在或解析失败时返回 Err（含描述信息），供调用方决定是否中止。
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("config.toml 不存在: {}", path.display()));
        }
        let content = fs::read_to_string(path)
            .map_err(|e| format!("读取 config.toml 失败: {}", e))?;
        let raw: RawConfig = toml::from_str(&content)
            .map_err(|e| format!("解析 config.toml 失败: {}", e))?;
        Ok(Self { log: raw.log })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_log_config() {
        let f = make_toml(r#"
[log]
level = "debug"
directory = "/tmp"
"#);
        let cfg = AppConfig::load(f.path()).unwrap();
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.log.directory, "/tmp");
    }

    #[test]
    fn test_missing_file_returns_err() {
        let result = AppConfig::load(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("config.toml 不存在"));
    }
}
