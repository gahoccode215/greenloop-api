package com.greenloop.order.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
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
    private String orderStatus;
    private List<OrderItemDTO> orderItems;
}
