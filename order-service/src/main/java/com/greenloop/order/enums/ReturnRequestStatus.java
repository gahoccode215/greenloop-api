package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum ReturnRequestStatus {
    PENDING_APPROVAL("Chờ duyệt"),
    APPROVED("Đã duyệt"),
    REJECTED("Từ chối"),
    RETURNING("Đang gửi hàng về"),
    RETURNED_TO_WAREHOUSE("Đã nhận hàng về kho"),
    RETURN_FAILED("Giao trả thất bại"),
    INSPECTED_APPROVED("Kiểm tra đạt"),
    INSPECTED_REJECTED("Kiểm tra không đạt"),
    COMPLETED("Hoàn tất"),
    CANCELLED("Đã hủy");

    private final String description;

    ReturnRequestStatus(String description) {
        this.description = description;
    }
}
