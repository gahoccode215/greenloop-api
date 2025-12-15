package com.greenloop.reward.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.*;

@Entity
@Table(name = "voucher_campaigns")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VoucherCampaign extends BaseEntity implements Serializable {
  @Column(name = "name", nullable = false, length = 100)
  private String name;

  @Column(name = "description", columnDefinition = "TEXT")
  private String description;

  @Column(name = "start_date", nullable = false)
  private LocalDateTime startDate;

  @Column(name = "end_date", nullable = false)
  private LocalDateTime endDate;

  @OneToMany(mappedBy = "campaign", cascade = CascadeType.ALL, orphanRemoval = true)
  @Builder.Default
  private List<Voucher> vouchers = new ArrayList<>();

  public void addVoucher(Voucher voucher) {
    vouchers.add(voucher);
    voucher.setCampaign(this);
  }
}
