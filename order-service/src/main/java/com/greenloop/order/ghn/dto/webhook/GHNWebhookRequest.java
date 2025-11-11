package com.greenloop.order.ghn.dto.webhook;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class GHNWebhookRequest {

    @JsonProperty("OrderCode")
    private String orderCode;  // Mã vận đơn GHN

    @JsonProperty("Status")
    private String status;  // ready_to_pick, picking, delivering, delivered...

    @JsonProperty("StatusText")
    private String statusText;

    @JsonProperty("CODAmount")
    private Integer codAmount;

    @JsonProperty("UpdatedDate")
    private String updatedDate;

    @JsonProperty("Description")
    private String description;
}
