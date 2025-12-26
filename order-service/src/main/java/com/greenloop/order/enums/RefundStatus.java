package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum RefundStatus {
    PENDING("Chờ xử lý"),
    PROCESSING("Đang xử lý"),
    COMPLETED("Đã hoàn tiền"),
    FAILED("Thất bại");

    private final String description;

    RefundStatus(String description) {
        this.description = description;
    }
}
