package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class CartNotFoundException extends BusinessException {
    public CartNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "CART_NOT_FOUND");
    }

    public CartNotFoundException(Long customerId) {
        super(
                "Không tìm thấy giỏ hàng của khách hàng: " + customerId,
                HttpStatus.NOT_FOUND,
                "CART_NOT_FOUND"
        );
    }
}
