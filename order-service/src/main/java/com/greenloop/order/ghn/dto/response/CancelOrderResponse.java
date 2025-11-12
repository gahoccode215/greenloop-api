package com.greenloop.order.ghn.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class CancelOrderResponse {

    @JsonProperty("order_code")
    private String orderCode;

    @JsonProperty("result")
    private Boolean result;

    @JsonProperty("message")
    private String message;
}
