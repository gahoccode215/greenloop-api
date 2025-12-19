package com.greenloop.order.dto.request;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class AddEcoPointsRequest {

    private String orderId;
    private String orderCode;
    private Long customerId;
    private Integer ecoPoints;
    private BigDecimal orderAmount;
    private LocalDateTime earnedAt;
}
