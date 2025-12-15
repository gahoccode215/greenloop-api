package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class OrderAccessDeniedException extends BusinessException {

    public OrderAccessDeniedException() {
        super(
                "Bạn không có quyền truy cập đơn hàng này",
                HttpStatus.FORBIDDEN,
                "ORDER_ACCESS_DENIED"
        );
    }

    public OrderAccessDeniedException(String orderId, Long userId) {
        super(
                String.format("Người dùng %d không có quyền truy cập đơn hàng %s", userId, orderId),
                HttpStatus.FORBIDDEN,
                "ORDER_ACCESS_DENIED"
        );
    }
}
