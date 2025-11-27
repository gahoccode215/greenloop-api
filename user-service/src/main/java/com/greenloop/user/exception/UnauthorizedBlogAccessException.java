package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedBlogAccessException extends BusinessException {

    public UnauthorizedBlogAccessException(String message) {
        super(message, HttpStatus.FORBIDDEN, "UNAUTHORIZED_BLOG_ACCESS");
    }

    public UnauthorizedBlogAccessException() {
        super("Bạn không có quyền truy cập hoặc chỉnh sửa blog này",
                HttpStatus.FORBIDDEN,
                "UNAUTHORIZED_BLOG_ACCESS");
    }
}
