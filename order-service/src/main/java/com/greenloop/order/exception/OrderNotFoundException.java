package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class OrderNotFoundException extends BusinessException {

    public OrderNotFoundException(String orderId) {
        super(
                "Không tìm thấy đơn hàng với ID: " + orderId,
                HttpStatus.NOT_FOUND,
                "ORDER_NOT_FOUND"
        );
    }
}
