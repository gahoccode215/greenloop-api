package com.greenloop.order.enums;

public enum PaymentMethod {
    COD("Thanh toán khi nhận hàng"),
    PAYOS("Thanh toán qua PayOS");

    private final String description;

    PaymentMethod(String description) {
        this.description = description;
    }

}
