package com.greenloop.reward.dto.event;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VoucherUsedEvent {
  private String orderId;
  private String orderCode;
  private Long customerId;
  private Long voucherUserId;
  private String voucherCode;
  private BigDecimal discountValue;
  private LocalDateTime usedAt;
}
