package com.greenloop.notification.dto.response;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class NotificationResponse {
  private Long id;
  private Long userId;
  private String title;
  private String message;
  private LocalDateTime createdAt;
  private boolean isRead;
}
