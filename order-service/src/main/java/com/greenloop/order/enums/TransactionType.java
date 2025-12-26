package com.greenloop.order.enums;

import lombok.Getter;

@Getter
public enum TransactionType {
    PAYMENT("Thanh toán đơn hàng"),
    REFUND("Hoàn tiền"),
    ADJUSTMENT("Điều chỉnh"),
    SHIPPING_FEE("Phí vận chuyển"),
    DISCOUNT("Giảm giá/Voucher");

    private final String description;

    TransactionType(String description) {
        this.description = description;
    }
}
