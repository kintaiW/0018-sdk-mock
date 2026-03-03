// FFI 指针转换辅助函数
// 所有 unsafe 操作集中在此模块，便于审计

use std::os::raw::c_void;

/// 安全地将 *mut c_void 解引用为指定类型的可变引用
/// 返回 None 如果指针为空
///
/// # Safety
/// 调用方必须保证指针指向有效的、对齐的内存，且生命周期足够长
pub unsafe fn ptr_as_mut<T>(ptr: *mut T) -> Option<&'static mut T> {
    if ptr.is_null() {
        None
    } else {
        Some(&mut *ptr)
    }
}

/// 安全地将 *const u8 + 长度转为 &[u8]
/// 返回 None 如果指针为空或长度为0
///
/// # Safety
/// 调用方必须保证内存有效
pub unsafe fn ptr_to_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() || len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(ptr, len))
    }
}

/// 安全地将 *mut u8 + 长度转为 &mut [u8]
///
/// # Safety
/// 调用方必须保证内存有效
pub unsafe fn ptr_to_slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() || len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts_mut(ptr, len))
    }
}

/// 将 Vec<u8> 的内容拷贝到 C 输出缓冲区，并设置实际长度
/// out_buf: 输出缓冲区指针
/// out_len: 输出缓冲区容量指针（调用后更新为实际写入长度）
///
/// # Safety
/// 调用方保证缓冲区足够大
pub unsafe fn write_output(data: &[u8], out_buf: *mut u8, out_len: *mut u32) -> bool {
    if out_buf.is_null() || out_len.is_null() {
        return false;
    }
    let capacity = *out_len as usize;
    if data.len() > capacity {
        return false;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, data.len());
    *out_len = data.len() as u32;
    true
}
