package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class AccountDisabledException extends BusinessException {
    public AccountDisabledException() {
        super("Tài khoản chưa kích hoạt hoặc bị vô hiệu hóa", HttpStatus.FORBIDDEN, "ACCOUNT_DISABLED");
    }
}