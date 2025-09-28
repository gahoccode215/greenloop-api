package com.greeloop.user.exception;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends BusinessException {
    public UserNotFoundException(Long userId) {
        super("User with ID " + userId + " not found", HttpStatus.NOT_FOUND, "USER_NOT_FOUND");
    }
}