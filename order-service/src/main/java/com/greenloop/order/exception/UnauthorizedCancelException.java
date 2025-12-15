package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedCancelException extends BusinessException{
    public UnauthorizedCancelException(String message) {
        super(message, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED_CANCEL");
    }
}
