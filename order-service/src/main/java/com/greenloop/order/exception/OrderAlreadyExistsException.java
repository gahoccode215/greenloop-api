package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class OrderAlreadyExistsException extends BusinessException {
    public OrderAlreadyExistsException(String orderCode) {
        super(
                "Đơn hàng với mã " + orderCode + " đã tồn tại",
                HttpStatus.CONFLICT,
                "ORDER_ALREADY_EXISTS"
        );
    }
}
