package com.greenloop.reward.dto.event;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderCompletedEvent {
  private String orderId;
  private String orderCode;
  private Long customerId;
  private BigDecimal totalAmount;
  private LocalDateTime completedAt;
  private Integer totalEcoPoints;
  private List<ProductEcoPoint> products;

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ProductEcoPoint {
    private Long productId;
    private Integer ecoPointValue;
    private String newStatus;
  }
}
