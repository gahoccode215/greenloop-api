package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class EmployeeNotFoundException extends BusinessException {
  public EmployeeNotFoundException(String message) {
    super(message, HttpStatus.NOT_FOUND, "EMPLOYEE_NOT_FOUND");
  }
}
