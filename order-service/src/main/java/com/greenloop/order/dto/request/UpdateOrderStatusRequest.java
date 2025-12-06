package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateOrderStatusRequest {
    private OrderStatus newStatus;
    private String reason;
    private String goshipShipmentId;
    private String goshipTrackingCode;
    private String carrier;
}
