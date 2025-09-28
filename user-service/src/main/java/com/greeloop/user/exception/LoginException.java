package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class LoginException extends BusinessException{
    public LoginException() {
        super("Email hoặc mật khẩu không chính xác", HttpStatus.BAD_REQUEST, "LOGIN_ERROR");
    }
}
