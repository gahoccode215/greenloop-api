package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class FileUploadException extends BusinessException {
    public FileUploadException(String message) {
        super(message, HttpStatus.INTERNAL_SERVER_ERROR, "FILE_UPLOAD_FAILED");
    }

    public FileUploadException() {
        super("Không thể upload file", HttpStatus.INTERNAL_SERVER_ERROR, "FILE_UPLOAD_FAILED");
    }
}
