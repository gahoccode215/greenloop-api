package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum ReturnType {
    REFUND("Hoàn tiền");

    private final String description;

    ReturnType(String description) {
        this.description = description;
    }
}
