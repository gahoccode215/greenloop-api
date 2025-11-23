package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VoucherResponse {
<<<<<<< HEAD
  private Long voucherId;
  private Long campaignId;
  private String code;
  private String description;
  private VoucherStatus voucherStatus;
  private VoucherType voucherType;
  private BigDecimal value;
  private BigDecimal minOrderValue;
  private BigDecimal maxDiscount;
  private LocalDateTime expiryDate;
  private Integer quantity;
  private Long pointToRedeem;
  private Boolean active;
=======
    private Long voucherId;
    private Long campaignId;
    private String code;
    private String name;
    private String description;
    private VoucherStatus voucherStatus;
    private VoucherType voucherType;
    private BigDecimal value;
    private BigDecimal minOrderValue;
    private BigDecimal maxDiscount;
    private LocalDateTime expiryDate;
    private Integer quantity;
    private Integer availableQuantity;
    private Integer pointToRedeem;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Long updateBy;
    private Boolean active;
>>>>>>> 72d9b53043cee7b8784c1d48740c6fc6821d00ca
}
