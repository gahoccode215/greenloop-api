package com.greenloop.product.service;

import com.greenloop.product.dto.event.NotificationEvent;

public interface NotificationProducer {
    void sendNotificationMessage(NotificationEvent notificationEvent);
}