package com.greenloop.product.exception;

import com.greenloop.product.enums.ErrorCode;
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

    public BusinessException(String customMessage, ErrorCode errorCode) {
        super(errorCode.name());
        this.errorCode = errorCode.getCode();
        this.message = customMessage;
        this.status = errorCode.getStatus();
    }

    public BusinessException(String message, HttpStatus httpStatus, String errorCode) {
        super(message);
        this.message = message;
        this.status = httpStatus;
        this.errorCode = errorCode;
    }
}
