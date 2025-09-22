package com.greeloop.user.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class EmailAlreadyExistsException extends BusinessException {
    private final String email;

    public EmailAlreadyExistsException(String email) {
        super("Email đã tồn tại: " + email, HttpStatus.CONFLICT, "EMAIL_ALREADY_EXISTS");
        this.email = email;
    }
}
