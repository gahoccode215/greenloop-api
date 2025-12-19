package com.greenloop.reward.dto.request;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VoucherUsedRequest {
  private String orderId;
  private String orderCode;
  private Long customerId;
  private Long voucherUserId;
  private String voucherCode;
  private BigDecimal discountValue;
  private LocalDateTime usedAt;
}
