package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class InsufficientEcoPointsException extends BusinessException {

    public InsufficientEcoPointsException(Long customerId, int required, int available) {
        super(
                String.format("Khách hàng ID %d không đủ điểm. Cần: %d, Có: %d",
                        customerId, required, available),
                HttpStatus.BAD_REQUEST,
                "INSUFFICIENT_ECO_POINTS"
        );
    }

    public InsufficientEcoPointsException(String message) {
        super(
                message,
                HttpStatus.BAD_REQUEST,
                "INSUFFICIENT_ECO_POINTS"
        );
    }
}
