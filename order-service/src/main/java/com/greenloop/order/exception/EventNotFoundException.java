package com.greenloop.order.exception;

import org.springframework.http.HttpStatus;

public class EventNotFoundException extends BusinessException {

    public EventNotFoundException(Long eventId) {
        super(
                "Sự kiện ID " + eventId + " không tồn tại",
                HttpStatus.NOT_FOUND,
                "EVENT_NOT_FOUND"
        );
    }
}
