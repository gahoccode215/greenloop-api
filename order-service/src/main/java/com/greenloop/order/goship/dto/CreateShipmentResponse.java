package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CreateShipmentResponse {

    @JsonProperty("code")
    private Integer code;

    @JsonProperty("status")
    private String status;

    @JsonProperty("message")
    private String message;

    @JsonProperty("id")
    private String id;

    @JsonProperty("cod")
    private String cod;

    @JsonProperty("fee")
    private String fee;

    @JsonProperty("tracking_number")
    private String trackingNumber;

    @JsonProperty("carrier")
    private String carrier;

    @JsonProperty("carrier_short_name")
    private String carrierShortName;

    @JsonProperty("created_at")
    private String createdAt;
}
