package com.greenloop.reward.service;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;

public interface RabbitMQConsumer {
  void consumeEcoPointTransactionMessage(EcoPointTransactionDTO ecoPointTransactionDTO);
}
