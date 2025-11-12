package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedCartAccessException extends BusinessException {
    public UnauthorizedCartAccessException(String message) {
        super(message, HttpStatus.FORBIDDEN, "UNAUTHORIZED_CART_ACCESS");
    }

    public UnauthorizedCartAccessException() {
        super(
                "Bạn không có quyền truy cập giỏ hàng này",
                HttpStatus.FORBIDDEN,
                "UNAUTHORIZED_CART_ACCESS"
        );
    }
}
