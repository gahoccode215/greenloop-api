package com.greenloop.reward.entity;

import com.greenloop.reward.enums.EcoPointStatus;
import jakarta.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import lombok.*;

@Entity
@Table(name = "eco_point_users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointUser extends BaseEntity implements Serializable {

  @Column(name = "user_id", nullable = false, unique = true)
  private Long userId;

  @Column(name = "total_points", nullable = false)
  private Integer totalPoints;

  @Column(name = "lifetime_points", nullable = false)
  private Integer lifetimePoints;

  @Column(name = "status", nullable = false, length = 50)
  @Enumerated(EnumType.STRING)
  private EcoPointStatus status;

  @OneToMany(mappedBy = "ecoPointUser", orphanRemoval = true, cascade = CascadeType.ALL)
  @Builder.Default
  private List<EcoPointTransaction> transactions = new ArrayList<>();

  public void addEcoPointTransaction(EcoPointTransaction ecoPointTransaction) {
    transactions.add(ecoPointTransaction);
    ecoPointTransaction.setEcoPointUser(this);
  }
}
