package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum TransactionStatus {
    PENDING("Đang chờ xử lý"),
    PROCESSING("Đang xử lý"),
    COMPLETED("Hoàn thành"),
    FAILED("Thất bại"),
    REFUNDED("Đã hoàn tiền"),
    CANCELLED("Đã hủy");

    private final String description;

    TransactionStatus(String description) {
        this.description = description;
    }
}
