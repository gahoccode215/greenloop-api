package com.greenloop.order.command.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ShippingStatusChangedEvent {

    private String orderId;

    private Integer oldStatus;

    private Integer newStatus;

    private String statusText;

    private String trackingUrl;

    private String carrier;
}
