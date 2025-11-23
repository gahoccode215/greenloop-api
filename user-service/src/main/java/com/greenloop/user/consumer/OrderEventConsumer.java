package com.greenloop.user.consumer;

import com.greenloop.user.dto.event.OrderCheckedOutEvent;
import com.greenloop.user.service.EcoPointService;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class OrderEventConsumer {

  private final EcoPointService ecoPointService;

  @Bean
  public Consumer<OrderCheckedOutEvent> orderCheckedOutConsumer() {
    return event -> {
      log.info(
          "Received OrderCheckedOutEvent for customer: {}, totalEcoPoints: {}",
          event.getCustomerId(),
          event.getTotalEcoPoints());

      if (event.getTotalEcoPoints() != null && event.getTotalEcoPoints() > 0) {
        ecoPointService.addEcoPoints(event.getCustomerId(), event.getTotalEcoPoints());
      }
    };
  }
}
