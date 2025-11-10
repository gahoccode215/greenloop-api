package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class ShippingOrderResponse {

    @JsonProperty("order_code")
    private String orderCode;  // Mã vận đơn GHN

    @JsonProperty("sort_code")
    private String sortCode;  // Mã sắp xếp

    @JsonProperty("trans_type")
    private String transType;

    @JsonProperty("ward_encode")
    private String wardEncode;

    @JsonProperty("district_encode")
    private String districtEncode;

    @JsonProperty("fee")
    private FeeDetail fee;

    @JsonProperty("total_fee")
    private Integer totalFee;  // Tổng phí

    @JsonProperty("expected_delivery_time")
    private String expectedDeliveryTime;  // Thời gian giao dự kiến

    @Data
    public static class FeeDetail {
        private Integer main_service;
        private Integer insurance;
        private Integer station_do;
        private Integer station_pu;
        private Integer return_fee;
        private Integer r2s;
        private Integer coupon;
    }
}
