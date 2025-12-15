package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InvalidShippingRateException extends BusinessException {
    public InvalidShippingRateException(String rateId) {
        super(
                String.format("Đơn vị vận chuyển '%s' không hợp lệ hoặc đã hết hạn", rateId),
                HttpStatus.BAD_REQUEST,
                "INVALID_SHIPPING_RATE"
        );
    }
}
