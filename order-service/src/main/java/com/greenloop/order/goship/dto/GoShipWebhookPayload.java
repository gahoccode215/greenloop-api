package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class GoShipWebhookPayload {

    @JsonProperty("event")
    private String event; // shipment.created, shipment.updated, shipment.delivered...

    @JsonProperty("data")
    private ShipmentData data;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ShipmentData {

        @JsonProperty("id")
        private String id; // Shipment ID

        @JsonProperty("tracking_code")
        private String trackingCode;

        @JsonProperty("status")
        private String status; // pending, picking, picked_up, in_transit, delivering, delivered, failed...

        @JsonProperty("carrier")
        private String carrier;

        @JsonProperty("updated_at")
        private LocalDateTime updatedAt;

        @JsonProperty("delivered_at")
        private LocalDateTime deliveredAt;

        @JsonProperty("note")
        private String note;

        @JsonProperty("cod_amount")
        private BigDecimal codAmount;
    }
}
