package com.greenloop.order.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AddEcoPointsRequest {
    private String orderId;
    private String orderCode;
    private Long customerId;
    private Integer ecoPoints;
    private BigDecimal orderAmount;
    private LocalDateTime earnedAt;
}
