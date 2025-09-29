package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class VerifyEmailException extends BusinessException{
    public VerifyEmailException(String message,  String errorCode) {
        super(message, HttpStatus.BAD_REQUEST, errorCode);
    }
}
