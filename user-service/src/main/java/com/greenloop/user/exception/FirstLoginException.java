package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class FirstLoginException extends BusinessException {
  public FirstLoginException() {
    super("Tài khoản mới tạo yêu cầu đổi mật khẩu", HttpStatus.FORBIDDEN, "FIRST_LOGIN_REQUIRED");
  }
}
