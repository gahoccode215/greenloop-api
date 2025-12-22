package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InvalidReturnRequestException extends BusinessException {

    public InvalidReturnRequestException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "INVALID_RETURN_REQUEST");
    }
}
