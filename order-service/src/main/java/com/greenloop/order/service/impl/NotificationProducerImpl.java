package com.greenloop.order.service.impl;

import com.greenloop.order.dto.event.NotificationEvent;
import com.greenloop.order.service.NotificationProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationProducerImpl implements NotificationProducer {
    private final RabbitTemplate rabbitTemplate;

    @Value("${rabbitmq.exchangeName}")
    private String exchange;

    @Value("${rabbitmq.notification-routing-key}")
    private String notificationRoutingKey;

    @Override
    public void sendNotificationMessage(NotificationEvent notificationEvent) {
        rabbitTemplate.convertAndSend(exchange, notificationRoutingKey, notificationEvent);
    }
}
