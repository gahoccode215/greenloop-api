package com.greenloop.event.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.*;
import lombok.experimental.SuperBuilder;

@MappedSuperclass
@Getter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Setter
public abstract class BaseEntity implements Serializable {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "is_active", nullable = false)
  @Builder.Default
  private boolean isActive = true;

  @Version @Builder.Default private Integer version = 1;

  @Column(name = "created_at", nullable = false)
  @Builder.Default
  private LocalDateTime createdAt = LocalDateTime.now();

  @Column(name = "updated_at", nullable = false)
  @Builder.Default
  private LocalDateTime updatedAt = LocalDateTime.now();

  @Column(name = "created_by")
  private Long createdBy;

  @Column(name = "updated_by")
  private Long updatedBy;

  @PreUpdate
  @PrePersist
  public void updateAt() {
    this.updatedAt = LocalDateTime.now();
  }

  public void activate(boolean isActive) {
    this.isActive = isActive;
  }

  public void updatedBy(Long updatedBy) {
    if (updatedBy != null) {
      this.updatedBy = updatedBy;
    }
  }

  public void createdBy(Long createdBy) {
    if (createdBy != null) {
      this.createdBy = createdBy;
    }
  }
}
