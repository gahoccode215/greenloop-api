package com.greenloop.order.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ShipmentInfoResponse {
    private String shipmentId;
    private String trackingNumber;
    private String carrier;
    private String fee;
    private String createdAt;
}
