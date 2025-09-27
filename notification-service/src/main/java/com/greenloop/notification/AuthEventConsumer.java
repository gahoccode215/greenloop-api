package com.greenloop.notification;

import com.greenloop.notification.payload.UserRegistrationEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
public class AuthEventConsumer {
    @RabbitListener(queues = "${rabbitmq.queue.name}")
    public void handleRegistrationEvent(UserRegistrationEvent event){
        log.info("Received registration event: {}", event);
    }
}
