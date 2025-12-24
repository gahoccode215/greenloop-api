package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class OrderCompletionExpiredException extends BusinessException {
    public OrderCompletionExpiredException(String orderId, int daysLimit) {
        super(
                String.format(
                        "Đã quá thời hạn %d ngày để hoàn thành đơn hàng %s. " +
                                "Đơn hàng sẽ được tự động hoàn thành.",
                        daysLimit, orderId
                ),
                HttpStatus.BAD_REQUEST,
                "ORDER_COMPLETION_EXPIRED"
        );
    }
}
