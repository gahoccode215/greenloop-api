package com.greenloop.order.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReturnShipmentInfoResponse {

    private String shipmentId;
    private String trackingNumber;
    private String carrier;
    private String fee;
    private String createdAt;
}
