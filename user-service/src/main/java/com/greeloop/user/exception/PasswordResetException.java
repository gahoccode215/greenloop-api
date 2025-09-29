package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class PasswordResetException extends BusinessException{
    public PasswordResetException(String message, String errorCode) {
        super(message, HttpStatus.BAD_REQUEST, errorCode);
    }
}
