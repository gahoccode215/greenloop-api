package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InvalidPaymentException extends BusinessException {

    public InvalidPaymentException(String message) {
        super(
                message,
                HttpStatus.BAD_REQUEST,
                "INVALID_PAYMENT"
        );
    }
}
