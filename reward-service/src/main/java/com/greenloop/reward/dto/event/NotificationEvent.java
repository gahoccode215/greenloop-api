package com.greenloop.reward.dto.event;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class NotificationEvent {
  private Long userId;
  private String title;
  private String message;
}
