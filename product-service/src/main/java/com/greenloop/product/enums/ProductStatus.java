package com.greenloop.product.enums;

public enum ProductStatus {
    PENDING,      // Đang chờ xử lý
    AVAILABLE,    // Sẵn sàng bán
    RESERVED,     // Đã đặt (giữ chỗ cho đơn hàng)
    SOLD,         // Đã bán & giao thành công
    UNAVAILABLE,  // Không khả dụng
    RETURNED      // Đã trả lại (từ đơn hàng thất bại)
}
