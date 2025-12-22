package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ReturnItemNotFoundException extends BusinessException {

    public ReturnItemNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "RETURN_ITEM_NOT_FOUND");
    }
}
