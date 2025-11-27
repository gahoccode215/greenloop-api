package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class BlogNotFoundException extends BusinessException {

    public BlogNotFoundException(Long id) {
        super(
                String.format("Không tìm thấy blog với ID: %d", id),
                HttpStatus.NOT_FOUND,
                "BLOG_NOT_FOUND");
    }

    public BlogNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "BLOG_NOT_FOUND");
    }
}
