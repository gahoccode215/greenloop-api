package com.greenloop.order.dto.response;

import com.greenloop.order.dto.OrderItemDTO;
import com.greenloop.order.dto.ShippingAddressDTO;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderResponse {

    private String orderId;
    private String orderCode;
    private Long customerId;

    private BigDecimal totalPrice;
    private BigDecimal shippingFee;

    private OrderStatus orderStatus;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;
    private String paymentTransactionId;

    private String carrier;
    private LocalDateTime expectedDeliveryTime;
    private String shippingStatus;
    private String goshipShipmentId;
    private String goshipTrackingCode;

    private ShippingAddressDTO shippingAddress;
    private List<OrderItemDTO> orderItems;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
