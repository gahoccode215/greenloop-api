package com.greenloop.order.enums;

public enum PaymentMethod {
    COD("Thanh toán khi nhận hàng"),
    VNPAY("Thanh toán qua VNPAY");

    private final String description;

    PaymentMethod(String description) {
        this.description = description;
    }

}
