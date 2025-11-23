package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class ShippingRateNotFoundException extends BusinessException {
    public ShippingRateNotFoundException(String message) {
        super(
                message,
                HttpStatus.NOT_FOUND,
                "SHIPPING_RATE_NOT_FOUND"
        );
    }
}
