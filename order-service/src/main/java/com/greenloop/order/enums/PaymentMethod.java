package com.greenloop.order.enums;

public enum PaymentMethod {
    COD("Thanh toán khi nhận hàng"),
    VNPAY("Thanh toán qua VNPAY"),
    PAYOS("Thanh toán qua PayOS");

    private final String description;

    PaymentMethod(String description) {
        this.description = description;
    }

}
