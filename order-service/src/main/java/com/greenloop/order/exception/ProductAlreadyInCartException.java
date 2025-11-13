package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ProductAlreadyInCartException extends BusinessException{
    public ProductAlreadyInCartException(String message, HttpStatus httpStatus, String errorCode) {
        super(message, httpStatus, errorCode);
    }
    public ProductAlreadyInCartException() {
        super("Sản phẩm đã có trong giỏ hàng", HttpStatus.BAD_REQUEST, "PRODUCT_ALREADY_IN_CART");
    }
}
