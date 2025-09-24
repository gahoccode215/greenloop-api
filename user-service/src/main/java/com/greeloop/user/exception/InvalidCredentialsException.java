package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends BusinessException {
    public InvalidCredentialsException() {
        super("Invalid credentials", HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
    }
}