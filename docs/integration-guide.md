# libsdf_mock 集成使用指南

> 面向 C 开发者 · GM/T 0018-2023 纯软件模拟 SDK

---

## 1. 快速上手

### 1.1 你需要哪些文件

| 文件 | 说明 |
|------|------|
| `libsdf_mock.so`（Linux）/ `sdf_mock.dll`（Windows） | 动态库本体 |
| `sdf.h` | C 头文件，包含所有函数声明和常量 |
| `config.toml` | 日志配置，**必须存在**，否则 `SDF_OpenDevice` 报错 |
| `mock_keys.toml` | 预置密钥，可选；KEK 和内部 SM2 密钥需要在此配置 |

### 1.2 config.toml 最小配置

把下面内容保存为 `config.toml`，放在**可执行文件同目录**（或当前工作目录）：

```toml
[log]
level = "warn"       # 日志级别：error / warn / info / debug
directory = "./"     # 日志文件输出目录
```

### 1.3 三行编译命令（Linux）

```bash
# 编译你的程序，链接 libsdf_mock.so
gcc -o my_app my_app.c -I/path/to/sdf.h -L/path/to/lib -lsdf_mock

# 运行时告诉系统去哪里找 .so
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH

# 运行
./my_app
```

> **Windows**：链接时改为 `sdf_mock.dll`，头文件中 `SDF_API` 会自动切换为 `__declspec(dllimport)`。

---

## 2. 调用生命周期（必须遵守的顺序）

```
SDF_OpenDevice          ← 打开设备（全局初始化，加载配置）
    └── SDF_OpenSession ← 打开会话（后续所有操作都要用这个 handle）
            ├── SDF_ImportKey / SDF_GenerateKeyWithKEK  ← 准备密钥
            ├── SDF_Encrypt / SDF_Decrypt / SDF_HMACInit + Update + Final / ...
            └── SDF_DestroyKey   ← 用完必须销毁密钥句柄
        SDF_CloseSession ← 关闭会话
SDF_CloseDevice          ← 关闭设备
```

**一句话记忆**：先开设备，再开会话，操作完销毁密钥，最后倒序关闭。

### 跳过步骤会怎样？

| 遗漏的步骤 | 后续操作会收到的错误码 |
|-----------|----------------------|
| 没有 `SDF_OpenDevice` | `SDR_OPENDEVICE` (0x01000005) |
| 没有 `SDF_OpenSession` | `SDR_OPENDEVICE` (0x01000005) |
| 用了已销毁的会话句柄 | `SDR_INVALIDHANDLE` (0x0100001A) |

---

## 3. 密钥体系

Mock SDK 有三类密钥，用途不同，使用方式也不同：

### 3.1 KEK（密钥加密密钥）

- **是什么**：用来保护会话密钥的"主密钥"，类似于"信封"
- **在哪里配置**：`mock_keys.toml` 的 `[[kek_keys]]` 段
- **怎么用**：调用 `SDF_GenerateKeyWithKEK` 时传入索引号（从 1 开始）

```toml
[[kek_keys]]
index = 1
algorithm = "SM4"
value = "FEDCBA9876543210FEDCBA9876543210"  # 16字节 SM4 密钥，十六进制
```

### 3.2 内部 SM2 密钥对

- **是什么**：预存在"设备"里的 SM2 密钥对，用索引号访问，私钥不出设备
- **在哪里配置**：`mock_keys.toml` 的 `[[sign_keys]]` / `[[enc_keys]]` 段
- **怎么用**：`SDF_InternalSign_ECC`（签名）、`SDF_GenerateKeyWithIPK_ECC`（加密保护会话密钥）

### 3.3 会话密钥

- **是什么**：程序运行时临时生成或导入的对称密钥，用 `void*` 句柄引用
- **两种来源**：
  - `SDF_ImportKey`：你自己传入明文密钥字节
  - `SDF_GenerateKeyWithKEK`：设备随机生成，同时用 KEK 加密后给你
- **生命周期**：用完必须调 `SDF_DestroyKey` 释放

---

## 4. 三个常用场景

### 场景 A：完整性保护（HMAC-SM3）

**适用**：防止数据在传输或存储中被篡改（文件校验、API 请求签名等）

```
1. ImportKey     ← 导入共享密钥（通信双方事先约定）
2. HMACInit      ← 用密钥初始化 HMAC 计算器
3. HMACUpdate    ← 喂入数据（可多次调用处理大文件）
4. HMACFinal     ← 得到 32 字节 HMAC 值
5. 对比 HMAC     ← 验证时重新计算，对比是否相同
6. DestroyKey
```

完整代码见：[examples/demos/demo_integrity.c](../examples/demos/demo_integrity.c)

---

### 场景 B：机密性保护（SM4-CBC）

**适用**：加密传输敏感数据（报文加密、文件加密等）

```
1. ImportKey     ← 导入对称密钥（或用 GenerateKeyWithKEK）
2. Encrypt       ← 传入 IV + 明文，得到密文
3. （传输密文）
4. ImportKey     ← 接收方导入同一密钥
5. Decrypt       ← 传入相同 IV + 密文，得到明文
6. DestroyKey（两次）
```

> **注意**：CBC 模式要求明文长度是 16 的倍数；IV 每次加密应随机生成，不要复用。

完整代码见：[examples/demos/demo_confidential.c](../examples/demos/demo_confidential.c)

---

### 场景 C：身份认证（SM2 外部签名验签）

**适用**：证明消息来源可信（数字签名、代码签名等）

```
1. GenerateKeyPair_ECC  ← 生成 SM2 密钥对（或使用预置密钥）
2. HashInit/Update/Final ← 先对消息做 SM3 哈希（得到 32 字节摘要）
3. ExternalSign_ECC     ← 用私钥对摘要签名（使用 SGD_SM2_1 算法 ID）
4. （传输消息 + 签名）
5. 验证方重新计算摘要
6. ExternalVerify_ECC   ← 用公钥验签
```

完整代码见：[examples/demos/demo_auth.c](../examples/demos/demo_auth.c)

---

## 5. 错误码速查

| 错误码 | 十六进制 | 含义 | 常见原因 |
|--------|---------|------|---------|
| `SDR_OK` | `0x00000000` | 成功 | — |
| `SDR_OPENDEVICE` | `0x01000005` | 设备未打开 | 忘记 `SDF_OpenDevice`，或 `config.toml` 不存在 |
| `SDR_INVALIDHANDLE` | `0x0100001A` | 句柄无效 | 会话已关闭，或密钥已销毁 |
| `SDR_PARAMERR` | `0x01000100` | 参数错误 | 传入了 NULL 指针，或长度为 0 |
| `SDR_CONFIGERR` | `0x01000101` | 配置错误 | `config.toml` 不存在或格式错误 |
| `SDR_KEYNOTEXIST` | `0x01000008` | 密钥不存在 | `mock_keys.toml` 未配置对应索引的密钥 |
| `SDR_KEYINDEX` | `0x01000019` | 密钥索引越界 | 请求的索引号在配置文件中不存在 |
| `SDR_NOTSUPPORT` | `0x01000002` | 不支持 | RSA 接口、文件操作接口（Mock 未实现） |
| `SDR_VERIFYERR` | `0x0100000E` | 验签失败 | 签名与公钥/数据不匹配 |
| `SDR_SYMOPERR` | `0x0100000F` | 对称运算失败 | 密钥句柄无效，或数据长度不符合要求 |

---

## 6. 常见问题 FAQ

**Q：运行时报 `SDR_CONFIGERR`，怎么处理？**

`SDF_OpenDevice` 启动时会在两个位置查找 `config.toml`：
1. 可执行文件所在目录
2. 当前工作目录（`pwd`）

确保 `config.toml` 存在于其中任意一个位置即可。

---

**Q：不配置 `mock_keys.toml` 能用哪些功能？**

可以正常使用：
- `SDF_ImportKey`（明文导入密钥）
- `SDF_GenerateKeyPair_ECC`（临时生成 SM2 密钥对）
- 所有外部密钥的加解密、签名验签（`External*` 系列）
- SM3 哈希、HMAC-SM3

**需要** `mock_keys.toml` 才能使用：
- `SDF_GenerateKeyWithKEK` / `SDF_ImportKeyWithKEK`（KEK 加密保护）
- `SDF_InternalSign_ECC` / `SDF_InternalVerify_ECC`（内部密钥签名）
- `SDF_ExportSignPublicKey_ECC` / `SDF_ExportEncPublicKey_ECC`（导出内部公钥）

---

**Q：SM4-CBC 加密时明文长度不是 16 的倍数怎么办？**

需要自行填充到 16 字节对齐（常用 PKCS#7 填充）。Mock SDK 本身不做自动填充。

---

**Q：HMAC-SM3 和 `SDF_CalculateMAC` 有什么区别？**

| | HMAC-SM3 | SDF_CalculateMAC（SM4-CBC-MAC） |
|---|---|---|
| 底层算法 | SM3 哈希 + 密钥 | SM4-CBC 加密取最后块 |
| 输出长度 | 32 字节 | 16 字节 |
| 数据长度限制 | 无限制 | 须为 16 的倍数 |
| 推荐场景 | 通用消息认证 | 金���报文 MAC |

---

**Q：Windows 和 Linux 的差异？**

| 项目 | Linux | Windows |
|------|-------|---------|
| 库文件名 | `libsdf_mock.so` | `sdf_mock.dll` |
| 链接参数 | `-lsdf_mock` | 链接 `.lib` 导入库 |
| 运行时路径 | `LD_LIBRARY_PATH` | 将 `.dll` 放在 `PATH` 或程序目录 |
| 日志路径分隔符 | `/` | `\` 或 `/` 均可 |

---

## 附：mock_keys.toml 完整示例

```toml
[device]
manufacturer = "MockDevice"
device_name  = "SDF_MOCK_V1"
device_serial = "MOCK20250101"

[root_key]
value = "0123456789ABCDEF0123456789ABCDEF"

# KEK 索引从 1 开始
[[kek_keys]]
index = 1
algorithm = "SM4"
value = "FEDCBA9876543210FEDCBA9876543210"

# SM2 签名密钥对，索引从 1 开始
[[sign_keys]]
index = 1
private_key = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
public_key  = "04BB34D0B28F49ABAFAD1AEE5E44B489B730B8B2A2CB6CC068C8B9DABE7C1F0D0809DBAAD5D932A64D5FF9C5C4B5E3B2CE1DB05E3F7B2F16EAEF87AAA6E9B07C0A"

# SM2 加密密钥对，索引从 1 开始
[[enc_keys]]
index = 1
private_key = "56B96C94AF649D75F1738B4A2A0E563D39B1D488E3B9C42D2E7E7C6E5CF2D3B7"
public_key  = "04C0D5E3A2B1F49876543210FEDCBA9876543210FEDCBA9876543210FEDCBA98760102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
```
