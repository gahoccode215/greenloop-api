package com.greenloop.reward.entity;

import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import jakarta.persistence.*;
import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.*;

@Entity
@Table(name = "vouchers")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Voucher extends BaseEntity implements Serializable {

  @ManyToOne
  @JoinColumn(name = "campaign_id")
  private VoucherCampaign campaign;

  @Column(name = "code", nullable = false, length = 50, unique = true)
  private String code;

  @Column(name = "name", nullable = false)
  private String name;

  @Column(name = "description", columnDefinition = "TEXT")
  private String description;

  @Enumerated(EnumType.STRING)
  @Column(name = "type", nullable = false, length = 20)
  private VoucherType type;

  @Column(name = "value", nullable = false, precision = 10, scale = 2)
  private BigDecimal value;

  @Column(name = "min_order_value", precision = 10, scale = 2)
  private BigDecimal minOrderValue;

  @Column(name = "max_discount", precision = 10, scale = 2)
  private BigDecimal maxDiscount;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 15)
  private VoucherStatus status = VoucherStatus.ACTIVE;

  @Column(name = "expiry_date")
  private LocalDateTime expiryDate;

  @Column(name = "quantity")
  private Integer quantity;

  @Column(name = "point_to_redeem", nullable = false)
  private Long pointToRedeem;

  @OneToMany(mappedBy = "voucher", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<VoucherUser> voucherUsers = new ArrayList<>();
}
