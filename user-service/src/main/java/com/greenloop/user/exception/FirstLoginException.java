package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class FirstLoginException extends BusinessException {
    public FirstLoginException(String message) {
        super(message, HttpStatus.FORBIDDEN, "FIRST_LOGIN_REQUIRED");
    }
}
