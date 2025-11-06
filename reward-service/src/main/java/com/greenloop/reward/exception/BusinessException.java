package com.greenloop.reward.exception;

import com.greenloop.reward.enums.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public class BusinessException extends RuntimeException {
  private final String errorCode;
  private final String message;
  private final HttpStatus status;

  public BusinessException(ErrorCode errorCode) {
    super(errorCode.name());
    this.errorCode = errorCode.getCode();
    this.message = errorCode.getMessage();
    this.status = errorCode.getStatus();
  }
}
