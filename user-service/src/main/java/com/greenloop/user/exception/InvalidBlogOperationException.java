package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class InvalidBlogOperationException extends BusinessException {

  public InvalidBlogOperationException(String message) {
    super(message, HttpStatus.BAD_REQUEST, "INVALID_BLOG_OPERATION");
  }
}
