package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class ChangePasswordException extends BusinessException {
  public ChangePasswordException(String message) {
    super(message, HttpStatus.BAD_REQUEST, "PASSWORD_CHANGE_ERROR");
  }
}
