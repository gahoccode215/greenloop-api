package com.greenloop.order.dto;

import com.greenloop.order.enums.OrderStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderDTO {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private BigDecimal totalPrice;
    private OrderStatus orderStatus;
    private List<OrderItemDTO> orderItems;

    private String goshipShipmentId;
    private String goshipTrackingCode;
    private String carrier;
    private BigDecimal shippingFee;
    private LocalDateTime expectedDeliveryTime;
    private String shippingStatus;
}
