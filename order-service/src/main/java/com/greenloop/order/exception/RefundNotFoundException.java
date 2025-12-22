package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class RefundNotFoundException extends BusinessException {

    public RefundNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "REFUND_NOT_FOUND");
    }
}
