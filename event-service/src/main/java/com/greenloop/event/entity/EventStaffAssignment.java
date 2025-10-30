package com.greenloop.event.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import lombok.*;

@Entity
@Table(name = "event_staff_assignments")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class EventStaffAssignment extends BaseEntity implements Serializable {
  @Column(name = "staff_id", nullable = false)
  private Long staffId;

  @ManyToOne
  @JoinColumn(name = "event_id", nullable = false)
  private Event event;

  @Column(name = "is_store_manager", nullable = false)
  private boolean isStoreManager;
}
