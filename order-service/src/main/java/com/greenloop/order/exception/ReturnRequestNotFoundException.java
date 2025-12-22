package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ReturnRequestNotFoundException extends BusinessException {

    public ReturnRequestNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "RETURN_REQUEST_NOT_FOUND");
    }
}
