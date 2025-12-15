package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class OrderNotCancellableException extends BusinessException {

    public OrderNotCancellableException(String currentStatus) {
        super(
                String.format("Không thể hủy đơn hàng ở trạng thái '%s'", currentStatus),
                HttpStatus.BAD_REQUEST,
                "ORDER_NOT_CANCELLABLE"
        );
    }
}
