package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InvalidRefundException extends BusinessException {

    public InvalidRefundException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "INVALID_REFUND");
    }
}
