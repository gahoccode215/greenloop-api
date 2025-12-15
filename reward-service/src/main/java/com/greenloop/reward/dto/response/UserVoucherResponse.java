package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.VoucherType;
import com.greenloop.reward.enums.VoucherUserStatus;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserVoucherResponse {
  private Long voucherUserId;
  private Long voucherId;
  private String voucherCode;
  private String voucherName;
  private BigDecimal value;
  private BigDecimal minOrderValue;
  private BigDecimal maxDiscount;
  private LocalDateTime assignedAt;
  private VoucherUserStatus status;
  private Integer quantity;
  private LocalDateTime expiryDate;
  private VoucherUserStatus voucherUserStatus;
  private Boolean active;
  private VoucherType voucherType;
}
