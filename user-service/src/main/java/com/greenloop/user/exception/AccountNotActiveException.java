package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class AccountNotActiveException extends BusinessException {
  public AccountNotActiveException() {
    super(
        "Tài khoản chưa được kích hoạt hoặc đã bị vô hiệu hóa",
        HttpStatus.FORBIDDEN,
        "ACCOUNT_NOT_ACTIVE");
  }
}
