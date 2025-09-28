package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class EmailNotFoundException extends BusinessException{
    public EmailNotFoundException(String email) {
        super("Tài khoản với " + email + " này không tồn tại", HttpStatus.NOT_FOUND, "EMAIL_NOT_FOUND");
    }
}
