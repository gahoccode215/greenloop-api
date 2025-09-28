package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class EmailNotVerifiedException extends BusinessException {
    public EmailNotVerifiedException() {
        super("Tài khoản chưa kích hoạt", HttpStatus.FORBIDDEN, "EMAIL_NOT_VERIFIED");
    }
}