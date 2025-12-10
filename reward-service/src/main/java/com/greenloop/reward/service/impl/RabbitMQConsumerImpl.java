package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
import com.greenloop.reward.enums.ErrorCode;
import com.greenloop.reward.exception.BusinessException;
import com.greenloop.reward.service.EcoPointUserService;
import com.greenloop.reward.service.RabbitMQConsumer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@Slf4j
public class RabbitMQConsumerImpl implements RabbitMQConsumer {
  private final EcoPointUserService ecoPointUserService;

  @Override
  @RabbitListener(queues = {"${rabbitmq.eco-donation-queue}"})
  @Retryable(
      value = {BusinessException.class},
      maxAttempts = 3,
      backoff = @Backoff(delay = 8000))
  public void consumeEcoPointTransactionMessage(EcoPointTransactionDTO ecoPointTransactionDTO) {
//    log.info("Consuming eco point transaction for userId: " + ecoPointTransactionDTO.getUserId());
//    try {
////      ecoPointUserService.updateEcoPointUserBalance(ecoPointTransactionDTO);
//    } catch (Exception e) {
//      log.error(
//          "Failed to process eco point transaction for userId: "
//              + ecoPointTransactionDTO.getUserId(),
//          e);
//      throw new BusinessException(ErrorCode.INVALID_ECO_POINT_TRANSACTION);
//    }
  }
}
