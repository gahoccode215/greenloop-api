package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ShipmentResponse {

    @JsonProperty("id")
    private String id;

    @JsonProperty("tracking_code")
    private String trackingCode;

    @JsonProperty("carrier")
    private String carrier;

    @JsonProperty("status")
    private String status;

    @JsonProperty("total_fee")
    private BigDecimal totalFee;

    @JsonProperty("cod_amount")
    private BigDecimal codAmount;

    @JsonProperty("expected_delivery_time")
    private LocalDateTime expectedDeliveryTime;

    @JsonProperty("created_at")
    private LocalDateTime createdAt;
}
