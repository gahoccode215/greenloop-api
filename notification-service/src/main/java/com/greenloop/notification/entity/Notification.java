package com.greenloop.notification.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.*;

@Entity
@Table(name = "notifications")
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Notification {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "user_id", nullable = false)
  private Long userId;

  @Column(nullable = false)
  private String title;

  @Column(nullable = false)
  private String body;

  @Column(name = "is_read", nullable = false)
  @Builder.Default
  private boolean isRead = false;

  @Column(nullable = false)
  @Builder.Default
  private LocalDateTime createdAt = LocalDateTime.now();
}
