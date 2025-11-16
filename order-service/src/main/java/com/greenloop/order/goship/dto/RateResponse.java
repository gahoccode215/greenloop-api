package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class RateResponse {

    @JsonProperty("carrier")
    private String carrier; // Mã carrier (vtp, ghn, njv...)

    @JsonProperty("carrier_name")
    private String carrierName; // Tên carrier

    @JsonProperty("service_type")
    private String serviceType;

    @JsonProperty("total_fee")
    private BigDecimal totalFee;

    @JsonProperty("delivery_time")
    private String deliveryTime; // Thời gian giao hàng dự kiến

    @JsonProperty("available")
    private Boolean available;
}
