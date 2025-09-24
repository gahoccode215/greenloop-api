package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class PasswordChangeException extends BusinessException {
    public PasswordChangeException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "PASSWORD_CHANGE_ERROR");
    }
}
