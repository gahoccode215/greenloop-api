package com.greenloop.product.service.impl;

import com.greenloop.product.dto.event.EcoPointTransactionDTO;
import com.greenloop.product.service.EcoPointDonationProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EcoPointDonationProducerImpl implements EcoPointDonationProducer {
    private final RabbitTemplate rabbitTemplate;

    @Value("${rabbitmq.exchangeName}")
    private String exchange;

    @Value("${rabbitmq.eco-donation-routing-key}")
    private String ecoDonationRoutingKey;

    @Override
    public void sendEcoPointDonationMessage(EcoPointTransactionDTO ecoPointTransactionDTO) {
        log.info("Sending eco point donation message to queue for userId: " + ecoPointTransactionDTO.getUserId());
        rabbitTemplate.convertAndSend(exchange, ecoDonationRoutingKey, ecoPointTransactionDTO);
    }
}
