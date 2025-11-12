package com.greenloop.event.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import java.math.BigDecimal;
import lombok.*;

@Entity
@Table(name = "event_reports")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class EventReport extends BaseEntity implements Serializable {
  @ManyToOne
  @JoinColumn(name = "event_id", nullable = false)
  private Event event;

  @Column(name = "donations_count", nullable = false)
  @Builder.Default
  private Integer donationsCount = 0;

  @Column(name = "sales_count", nullable = false)
  @Builder.Default
  private Integer salesCount = 0;

  @Column(nullable = false, precision = 8, scale = 2)
  private BigDecimal revenue;

  @Column(columnDefinition = "TEXT")
  private String note;
}
