package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class EmailAlreadyExistsException extends BusinessException {

    public EmailAlreadyExistsException() {
        super("Email đã tồn tại", HttpStatus.CONFLICT, "EMAIL_ALREADY_EXISTS");
    }
}
