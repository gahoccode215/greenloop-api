package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class RateResponse {

    @JsonProperty("id")
    private String id;

    @JsonProperty("carrier_name")
    private String carrierName;

    @JsonProperty("carrier_logo")
    private String carrierLogo;

    @JsonProperty("carrier_short_name")
    private String carrierShortName;

    @JsonProperty("service")
    private String service;

    @JsonProperty("expected")
    private String expected;

    @JsonProperty("expected_txt")
    private String expectedTxt;

    @JsonProperty("is_apply_only")
    private Boolean isApplyOnly;

    @JsonProperty("promotion_id")
    private Integer promotionId;

    @JsonProperty("discount")
    private BigDecimal discount;

    @JsonProperty("weight_fee")
    private BigDecimal weightFee;

    @JsonProperty("location_first_fee")
    private BigDecimal locationFirstFee;

    @JsonProperty("location_step_fee")
    private BigDecimal locationStepFee;

    @JsonProperty("remote_area_fee")
    private BigDecimal remoteAreaFee;

    @JsonProperty("oil_fee")
    private BigDecimal oilFee;

    @JsonProperty("location_fee")
    private BigDecimal locationFee;

    @JsonProperty("cod_fee")
    private BigDecimal codFee;

    @JsonProperty("service_fee")
    private BigDecimal serviceFee;

    @JsonProperty("insurrance_fee")
    private BigDecimal insurranceFee;

    @JsonProperty("return_fee")
    private BigDecimal returnFee;

    @JsonProperty("total_fee")
    private BigDecimal totalFee;

    @JsonProperty("total_amount")
    private BigDecimal totalAmount;

    @JsonProperty("total_amount_carrier")
    private BigDecimal totalAmountCarrier;

    @JsonProperty("total_amount_shop")
    private BigDecimal totalAmountShop;

    @JsonProperty("price_table_id")
    private Integer priceTableId;

    @JsonProperty("report")
    private Report report;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Report {

        @JsonProperty("success_percent")
        private Double successPercent;

        @JsonProperty("return_percent")
        private Double returnPercent;

        @JsonProperty("avg_time_delivery")
        private Integer avgTimeDelivery;

        @JsonProperty("avg_time_delivery_format")
        private Integer avgTimeDeliveryFormat;

        @JsonProperty("score_percent")
        private Double scorePercent;
    }
}
