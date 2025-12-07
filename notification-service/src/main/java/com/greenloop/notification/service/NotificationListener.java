package com.greenloop.notification.service;

import com.greenloop.notification.dto.event.NotificationEvent;

public interface NotificationListener {
  void handleNotificationEvent(NotificationEvent notificationEvent);
}
