package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class PhoneNumberAlreadyExistsException extends BusinessException {

  public PhoneNumberAlreadyExistsException(String phoneNumber) {
    super(
        "Số điện thoại " + phoneNumber + " đã được sử dụng",
        HttpStatus.CONFLICT,
        "PHONE_NUMBER_ALREADY_EXISTS");
  }
}
