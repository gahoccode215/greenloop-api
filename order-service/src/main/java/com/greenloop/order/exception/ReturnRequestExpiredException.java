package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ReturnRequestExpiredException extends BusinessException {

    public ReturnRequestExpiredException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "RETURN_REQUEST_EXPIRED");
    }
}
