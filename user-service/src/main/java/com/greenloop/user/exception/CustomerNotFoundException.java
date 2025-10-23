package com.greenloop.user.exception;

import org.springframework.http.HttpStatus;

public class CustomerNotFoundException extends BusinessException {
    public CustomerNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND, "CUSTOMER_NOT_FOUND");
    }
    public CustomerNotFoundException(){
        super("Không tìm thấy khách hàng", HttpStatus.NOT_FOUND, "CUSTOMER_NOT_FOUND");
    }
}
