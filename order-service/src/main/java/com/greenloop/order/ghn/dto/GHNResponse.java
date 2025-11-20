package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class GHNResponse<T> {

    @JsonProperty("code")
    private Integer code;

    @JsonProperty("message")
    private String message;

    @JsonProperty("data")
    private T data;


    public boolean isSuccess() {
        return code != null && code == 200;
    }

    public boolean isError() {
        return code == null || code != 200;
    }
}
