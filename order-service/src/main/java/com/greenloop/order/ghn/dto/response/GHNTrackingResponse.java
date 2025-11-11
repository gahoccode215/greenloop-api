package com.greenloop.order.ghn.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class GHNTrackingResponse {

    @JsonProperty("order_code")
    private String orderCode;

    @JsonProperty("status")
    private String status;  // ready_to_pick, picking, delivering, delivered...

    @JsonProperty("status_text")
    private String statusText;  // Mô tả trạng thái

    @JsonProperty("to_name")
    private String toName;

    @JsonProperty("to_phone")
    private String toPhone;

    @JsonProperty("to_address")
    private String toAddress;

    @JsonProperty("cod_amount")
    private Integer codAmount;

    @JsonProperty("total_fee")
    private Integer totalFee;

    @JsonProperty("expected_delivery_time")
    private String expectedDeliveryTime;

    @JsonProperty("log")
    private List<LogEntry> log;  // Lịch sử trạng thái

    @Data
    public static class LogEntry {
        @JsonProperty("status")
        private String status;

        @JsonProperty("updated_date")
        private String updatedDate;

        @JsonProperty("description")
        private String description;
    }
}
