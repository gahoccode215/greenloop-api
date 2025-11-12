package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ProductNotFoundException extends BusinessException {
    public ProductNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "PRODUCT_NOT_FOUND");
    }

    public ProductNotFoundException(Long productId) {
        super(
                "Không tìm thấy sản phẩm với ID: " + productId,
                HttpStatus.NOT_FOUND,
                "PRODUCT_NOT_FOUND"
        );
    }
}
