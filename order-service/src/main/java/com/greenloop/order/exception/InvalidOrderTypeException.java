package com.greenloop.order.exception;

import com.greenloop.order.enums.OrderType;
import org.springframework.http.HttpStatus;

public class InvalidOrderTypeException extends BusinessException {

    public InvalidOrderTypeException(String orderId, OrderType expected, OrderType actual) {
        super(
                String.format("Order %s is not %s (actual: %s)", orderId, expected, actual),
                HttpStatus.BAD_REQUEST,
                "INVALID_ORDER_TYPE"
        );
    }
}
