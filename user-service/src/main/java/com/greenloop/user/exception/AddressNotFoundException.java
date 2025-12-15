package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class AddressNotFoundException extends BusinessException {

  public AddressNotFoundException(Long addressId, Long userId) {
    super(
        String.format("Không tìm thấy địa chỉ với ID: %d cho người dùng: %d", addressId, userId),
        HttpStatus.NOT_FOUND,
        "ADDRESS_NOT_FOUND");
  }

  public AddressNotFoundException(String message) {
    super(message, HttpStatus.NOT_FOUND, "ADDRESS_NOT_FOUND");
  }
}
