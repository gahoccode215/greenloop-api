package com.greenloop.notification.service.impl;

import com.greenloop.notification.dto.event.NotificationEvent;
import com.greenloop.notification.service.NotificationListener;
import com.greenloop.notification.service.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
@Slf4j
public  class NotificationListenerImpl implements NotificationListener {
    private final NotificationService notificationService;

    @Override
    @RabbitListener(queues = "${rabbitmq.notification-queue}")
    public void handleNotificationEvent(NotificationEvent notificationEvent) {
        log.info("Handling notification event: {}", notificationEvent);
        notificationService.createAndSend(notificationEvent);

    }
}