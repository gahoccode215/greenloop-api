package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class VoucherException extends BusinessException{
    public VoucherException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "VOUCHER_EXCEPTION");
    }
}
