package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class EmptyCartException extends BusinessException{
    public EmptyCartException() {
        super("Giỏ hàng rỗng", HttpStatus.BAD_REQUEST, "CART_EMPTY");
    }
}
