package com.greenloop.reward.service;

import com.greenloop.reward.dto.event.NotificationEvent;

public interface NotificationProducer {
  void sendNotificationMessage(NotificationEvent notificationEvent);
}
