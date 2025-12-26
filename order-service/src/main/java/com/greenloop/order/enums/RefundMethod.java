package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum RefundMethod {
    BANK_TRANSFER("Chuyển khoản ngân hàng");

    private final String description;

    RefundMethod(String description) {
        this.description = description;
    }
}
