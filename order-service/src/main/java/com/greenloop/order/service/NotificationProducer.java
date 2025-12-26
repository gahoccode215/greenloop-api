package com.greenloop.order.service;

import com.greenloop.order.dto.event.NotificationEvent;

public interface NotificationProducer {
    void sendNotificationMessage(NotificationEvent notificationEvent);
}
