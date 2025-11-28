package com.greenloop.order.enums;

public enum PaymentMethod {
    COD("Thanh toán khi nhận hàng"),
    PAYOS("Thanh toán qua PayOS"),

    CASH("Tiền mặt"),
    ECO_POINT("Thanh toán bằng điểm"),
    MIXED("Tiền mặt + Điểm");


    private final String description;

    PaymentMethod(String description) {
        this.description = description;
    }

}
