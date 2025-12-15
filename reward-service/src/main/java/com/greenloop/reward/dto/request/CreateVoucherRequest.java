package com.greenloop.reward.dto.request;

import com.greenloop.reward.enums.VoucherType;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.Data;

@Data
public class CreateVoucherRequest {

  private Long campaignId;

  @NotNull(message = "Voucher type is required")
  private VoucherType voucherType;

  @NotBlank(message = "Voucher name is required")
  private String name;

  private String description;

  @NotNull(message = "Voucher value is required")
  @DecimalMin(value = "0.01", message = "Voucher value must be greater than 0")
  private BigDecimal value;

  @DecimalMin(value = "1000", message = "Giá trị đơn hàng tối thiểu phải >= 1,000 VND")
  @DecimalMax(value = "500000", message = "Giá trị đơn hàng tối đa phải <= 500,000 VND")
  private BigDecimal minOrderValue;

  @DecimalMin(value = "1000", message = "Giảm giá tối thiểu phải >= 1,000 VND")
  @DecimalMax(value = "500000", message = "Giảm giá tối đa phải <= 500,000 VND")
  private BigDecimal maxDiscount;

  @NotNull(message = "Expiry date not null")
  @Future(message = "Expiry date must be in the future")
  private LocalDateTime expiryDate;

  @NotNull(message = "Quantity is required")
  @Min(value = 1, message = "Quantity must be at least 1")
  private Integer quantity;

  @NotNull(message = "Point to redeem is required")
  @Min(value = 0, message = "Point to redeem must be at least 1")
  private Integer pointToRedeem;
}
