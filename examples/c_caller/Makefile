# GM/T 0018 Mock SDK — C 示例编译说明
# 用法：在本目录下执行 make 即可

REPO_ROOT := ../..
LIB_DIR   := $(REPO_ROOT)/target/debug
INC_DIR   := $(REPO_ROOT)

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 -I$(INC_DIR)
LDFLAGS := -L$(LIB_DIR) -lsdf_mock -Wl,-rpath,$(LIB_DIR)

TARGET := demo

.PHONY: all clean build-lib

all: build-lib $(TARGET)

# 先编译 Rust 库
build-lib:
	cd $(REPO_ROOT) && cargo build

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
