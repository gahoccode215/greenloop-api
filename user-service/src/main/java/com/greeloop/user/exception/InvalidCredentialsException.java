package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends BusinessException {
    public InvalidCredentialsException() {
        super("Email hoặc mật khẩu không đúng", HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
    }
}