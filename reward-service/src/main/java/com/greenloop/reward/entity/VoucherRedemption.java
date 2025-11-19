package com.greenloop.reward.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.*;

@Entity
@Table(name = "voucher_redemptions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VoucherRedemption extends BaseEntity {

  @ManyToOne
  @JoinColumn(name = "voucher_user_id", nullable = false)
  private VoucherUser voucherUser;

  @Column(name = "order_id")
  private Long orderId;

  @Column(name = "discount_value", nullable = false, precision = 10, scale = 2)
  private BigDecimal discountValue;

  @Column(name = "redeemed_at", nullable = false)
  private LocalDateTime redeemedAt = LocalDateTime.now();
}
