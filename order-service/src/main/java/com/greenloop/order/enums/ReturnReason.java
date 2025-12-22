package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum ReturnReason {
    WRONG_ITEM("Giao sai hàng"),
    DEFECTIVE("Hàng lỗi"),
    NOT_AS_DESCRIBED("Không đúng mô tả"),
    CHANGED_MIND("Đổi ý"),
    OTHER("Lý do khác");

    private final String description;

    ReturnReason(String description) {
        this.description = description;
    }
}
