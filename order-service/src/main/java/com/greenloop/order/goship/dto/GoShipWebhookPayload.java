package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class GoShipWebhookPayload {

    @JsonProperty("gcode")
    private String gcode;  // GoShip shipment ID

    @JsonProperty("code")
    private String code;  // Carrier tracking code

    @JsonProperty("order_id")
    private String orderId;  // Your order code

    @JsonProperty("weight")
    private String weight;

    @JsonProperty("fee")
    private String fee;

    @JsonProperty("cod")
    private String cod;

    @JsonProperty("payer")
    private String payer;

    @JsonProperty("status")
    private String status;  // Status code (901, 902, 905, etc.)

    @JsonProperty("status_text")
    private String statusText;

    @JsonProperty("message")
    private String message;

    @JsonProperty("tracking_url")
    private String trackingUrl;

    @JsonProperty("description")
    private String description;

    @JsonProperty("sorting_code")
    private String sortingCode;

    @JsonProperty("return_sorting_code")
    private String returnSortingCode;

    @JsonProperty("is_return")
    private Integer isReturn;

    @JsonProperty("is_part_delivery")
    private Integer isPartDelivery;

    @JsonProperty("is_lost")
    private Integer isLost;
}
