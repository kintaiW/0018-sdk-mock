// 设备/会话上下文管理
// 每个 SDF_OpenDevice 创建一个 DeviceContext
// 每个 SDF_OpenSession 创建一个 SessionContext

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::key_mgr::KeyStore;
use crate::config::MockConfig;
use crate::crypto::sm3_ops::Sm3State;

static SESSION_HANDLE_COUNTER: AtomicU32 = AtomicU32::new(1);

/// 哈希运算上下文（每次 HashInit 创建一个）
#[derive(Debug, Clone)]
pub struct HashCtx {
    pub state: Sm3State,
    pub alg_id: u32,
    /// SM2 Hash with Z 时存储公钥（用于 SM3withSM2）
    pub pub_key: Option<[u8; 65]>,
}

/// HMAC 运算上下文
#[derive(Debug, Clone)]
pub struct HmacCtx {
    pub key_handle: u32,
    pub buffer: Vec<u8>,
}

/// 密钥协商中间态数据
#[derive(Debug, Clone)]
pub struct AgreementData {
    /// 本端临时私钥
    pub tmp_private: [u8; 32],
    /// 本端临时公钥
    pub tmp_public: [u8; 65],
    /// 本端长期私钥索引
    pub isk_index: u32,
    /// ID
    pub id: Vec<u8>,
}

/// 会话上下文（每个 SDF_OpenSession 独立一个）
pub struct SessionContext {
    pub handle: u32,
    pub key_store: KeyStore,
    /// 当前活跃的哈希上下文（每次 HashInit 覆盖）
    pub hash_ctx: Option<HashCtx>,
    /// 当前活跃的 HMAC 上下文
    pub hmac_ctx: Option<HmacCtx>,
    /// 密钥协商中间态
    pub agreement_data: Option<AgreementData>,
    /// 私钥访问授权集合（已授权的密钥索引）
    pub authorized_keys: std::collections::HashSet<u32>,
}

impl SessionContext {
    pub fn new(mock_cfg: &MockConfig) -> Self {
        let handle = SESSION_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut key_store = KeyStore::new();
        key_store.load_from_config(mock_cfg);
        Self {
            handle,
            key_store,
            hash_ctx: None,
            hmac_ctx: None,
            agreement_data: None,
            authorized_keys: std::collections::HashSet::new(),
        }
    }
}

/// 设备上下文（全局唯一，包含所有会话）
pub struct DeviceContext {
    pub mock_cfg: MockConfig,
    pub sessions: HashMap<u32, SessionContext>,
}

impl DeviceContext {
    pub fn new(mock_cfg: MockConfig) -> Self {
        Self { mock_cfg, sessions: HashMap::new() }
    }

    /// 创建新会话，返回会话句柄
    pub fn open_session(&mut self) -> u32 {
        let session = SessionContext::new(&self.mock_cfg);
        let handle = session.handle;
        self.sessions.insert(handle, session);
        log::debug!("打开会话: handle=0x{:08X}", handle);
        handle
    }

    /// 关闭会话
    pub fn close_session(&mut self, handle: u32) -> bool {
        let removed = self.sessions.remove(&handle).is_some();
        if removed {
            log::debug!("关闭会话: handle=0x{:08X}", handle);
        }
        removed
    }

    /// 获取会话（可变引用）
    pub fn get_session_mut(&mut self, handle: u32) -> Option<&mut SessionContext> {
        self.sessions.get_mut(&handle)
    }

    /// 获取会话（不可变引用）
    pub fn get_session(&self, handle: u32) -> Option<&SessionContext> {
        self.sessions.get(&handle)
    }
}
