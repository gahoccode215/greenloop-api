package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class GHNResponse<T> {
    private Integer code;
    private String message;
    private T data;

    @JsonProperty("code_message")
    private String codeMessage;

    public boolean isSuccess() {
        return code != null && code == 200;
    }
}
