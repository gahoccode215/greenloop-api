package com.greenloop.event.service;

import com.greenloop.event.dto.event.NotificationEvent;

public interface NotificationProducer {
  void sendNotificationMessage(NotificationEvent notificationEvent);
}
