package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ProductNotAvailableException extends BusinessException {
    public ProductNotAvailableException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "PRODUCT_NOT_AVAILABLE");
    }

    public ProductNotAvailableException(Long productId) {
        super(
                "Sản phẩm với ID " + productId + " không còn hàng hoặc không khả dụng",
                HttpStatus.BAD_REQUEST,
                "PRODUCT_NOT_AVAILABLE"
        );
    }
}
