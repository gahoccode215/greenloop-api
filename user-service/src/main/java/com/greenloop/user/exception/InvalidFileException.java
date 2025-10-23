package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class InvalidFileException extends BusinessException {
    public InvalidFileException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "INVALID_FILE");
    }

    public InvalidFileException() {
        super("File không hợp lệ", HttpStatus.BAD_REQUEST, "INVALID_FILE");
    }
}
