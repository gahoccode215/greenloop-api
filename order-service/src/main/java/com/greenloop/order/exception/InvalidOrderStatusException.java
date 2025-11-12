package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InvalidOrderStatusException extends BusinessException {
    public InvalidOrderStatusException(String currentStatus, String targetStatus) {
        super(
                String.format("Không thể chuyển trạng thái đơn hàng từ %s sang %s", currentStatus, targetStatus),
                HttpStatus.BAD_REQUEST,
                "INVALID_ORDER_STATUS"
        );
    }
}
