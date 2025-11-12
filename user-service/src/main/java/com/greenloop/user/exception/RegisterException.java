package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class RegisterException extends BusinessException{
    public RegisterException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "REGISTER_ERROR");
    }

}
