package com.greenloop.reward.dto.request;

import java.math.BigDecimal;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RedeemVoucherRequest {

  private Long voucherUserId;
  private Long orderId;
  private BigDecimal discountValue;
}
