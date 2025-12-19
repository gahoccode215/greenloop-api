package com.greenloop.reward.dto.request;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

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
