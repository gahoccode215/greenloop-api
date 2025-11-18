package com.greenloop.reward.entity;

import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.SourceType;
import jakarta.persistence.*;
import java.io.Serializable;
import lombok.*;

@Entity
@Table(name = "eco_point_transactions")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointTransaction extends BaseEntity implements Serializable {

  @Column(name = "user_id", nullable = false)
  private Long userId;

  @Column(name = "type", nullable = false, length = 50)
  @Enumerated(EnumType.STRING)
  private EcoPointType type;

  @Column(name = "points", nullable = false)
  private Integer points;

  @Column(name = "source_type", nullable = false, length = 50)
  @Enumerated(EnumType.STRING)
  private SourceType sourceType;

  @Column(name = "source_id", nullable = false)
  private Long sourceId;

  @Column(name = "description", columnDefinition = "TEXT")
  private String description;

  @ManyToOne(fetch = FetchType.LAZY)
  private EcoPointUser ecoPointUser;
}
