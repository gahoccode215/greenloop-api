package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedOrderAccessException extends BusinessException {
    public UnauthorizedOrderAccessException(String orderId, Long customerId) {
        super(
                String.format("Bạn không có quyền truy cập đơn hàng %s", orderId),
                HttpStatus.FORBIDDEN,
                "UNAUTHORIZED_ORDER_ACCESS"
        );
    }

    public UnauthorizedOrderAccessException(String message) {
        super(message, HttpStatus.FORBIDDEN, "UNAUTHORIZED_ORDER_ACCESS");
    }
}
