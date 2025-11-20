package com.greenloop.order.ghn.exception;

import lombok.Getter;

@Getter
public class GHNException extends RuntimeException {

    private final Integer code;
    private final String message;

    public GHNException(Integer code, String message) {
        super(message);
        this.code = code;
        this.message = message;
    }

    public GHNException(String message) {
        super(message);
        this.code = null;
        this.message = message;
    }


}
