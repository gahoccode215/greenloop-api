package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class OrderNotDeliveredException extends BusinessException {
    public OrderNotDeliveredException(String orderId) {
        super(
                String.format("Đơn hàng %s chưa được giao hàng", orderId),
                HttpStatus.BAD_REQUEST,
                "ORDER_NOT_DELIVERED"
        );
    }
}
