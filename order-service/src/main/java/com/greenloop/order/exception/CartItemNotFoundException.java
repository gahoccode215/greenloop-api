package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class CartItemNotFoundException extends BusinessException {
    public CartItemNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "CART_ITEM_NOT_FOUND");
    }

    public CartItemNotFoundException(Long cartItemId) {
        super(
                "Không tìm thấy sản phẩm trong giỏ hàng với ID: " + cartItemId,
                HttpStatus.NOT_FOUND,
                "CART_ITEM_NOT_FOUND"
        );
    }
}
