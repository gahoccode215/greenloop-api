package com.greenloop.reward.entity;

import com.greenloop.reward.enums.VoucherSource;
import com.greenloop.reward.enums.VoucherUserStatus;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.*;

@Entity
@Table(name = "voucher_users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VoucherUser extends BaseEntity {

  @ManyToOne
  @JoinColumn(name = "voucher_id", nullable = false)
  private Voucher voucher;

  @Column(name = "user_id", nullable = false)
  private Long userId;

  @Column(name = "assigned_at", nullable = false)
  private LocalDateTime assignedAt = LocalDateTime.now();

  @Column(name = "redeemed_at")
  private LocalDateTime redeemedAt;

  @Column(name = "quantity", nullable = false)
  private Long quantity;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 15)
  private VoucherUserStatus status = VoucherUserStatus.AVAILABLE;

  @Enumerated(EnumType.STRING)
  @Column(name = "source", nullable = false, length = 20)
  private VoucherSource source;

  @OneToMany(mappedBy = "voucherUser", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<VoucherRedemption> redemptions = new ArrayList<>();
}
