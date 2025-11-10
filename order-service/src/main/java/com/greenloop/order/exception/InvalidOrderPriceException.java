package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InvalidOrderPriceException extends BusinessException {
    public InvalidOrderPriceException() {
        super(
                "Giá trị đơn hàng phải lớn hơn 0",
                HttpStatus.BAD_REQUEST,
                "INVALID_ORDER_PRICE"
        );
    }
}
