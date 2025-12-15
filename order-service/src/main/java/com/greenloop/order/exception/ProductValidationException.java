package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ProductValidationException extends BusinessException {

    public ProductValidationException(){
        super("Sản phẩm không hợp lệ", HttpStatus.BAD_REQUEST, "PRODUCT_VALIDATION_FAILED");
    }

    public ProductValidationException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "PRODUCT_VALIDATION_FAILED");
    }

    public ProductValidationException(Long productId, String reason) {
        super(
                String.format("Sản phẩm ID %d không hợp lệ: %s", productId, reason),
                HttpStatus.BAD_REQUEST,
                "PRODUCT_VALIDATION_FAILED"
        );
    }

    public ProductValidationException(String productName, String reason) {
        super(
                String.format("Sản phẩm '%s' không hợp lệ: %s", productName, reason),
                HttpStatus.BAD_REQUEST,
                "PRODUCT_VALIDATION_FAILED"
        );
    }
}
