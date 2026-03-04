# GM/T 0018 Mock SDK — Demo 示例编译
#
# 用法：
#   make              # 编译全部三个 demo
#   make demo_integrity
#   make demo_confidential
#   make demo_auth
#   make run          # 依次运行全部 demo
#   make clean        # 清理编译产物

REPO_ROOT := ../..
LIB_DIR   := $(REPO_ROOT)/target/debug
INC_DIR   := $(REPO_ROOT)

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 -I$(INC_DIR)
LDFLAGS := -L$(LIB_DIR) -lsdf_mock -Wl,-rpath,$(LIB_DIR)

TARGETS := demo_integrity demo_confidential demo_auth

.PHONY: all build-lib run clean

all: build-lib $(TARGETS)

# 先编译 Rust 动态库
build-lib:
	cd $(REPO_ROOT) && cargo build

demo_integrity: demo_integrity.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

demo_confidential: demo_confidential.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

demo_auth: demo_auth.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# 依次运行三个 demo（config.toml 从项目根复制过来）
run: all
	@cp -n $(REPO_ROOT)/config.toml . 2>/dev/null || true
	@echo ""; echo "═══ 完整性保护 Demo（HMAC-SM3）═══"
	LD_LIBRARY_PATH=$(LIB_DIR) ./demo_integrity
	@echo ""; echo "═══ 机密性保护 Demo（SM4-CBC）═══"
	LD_LIBRARY_PATH=$(LIB_DIR) ./demo_confidential
	@echo ""; echo "═══ 身份认证 Demo（SM2 签名验签）═══"
	LD_LIBRARY_PATH=$(LIB_DIR) ./demo_auth

clean:
	rm -f $(TARGETS)
