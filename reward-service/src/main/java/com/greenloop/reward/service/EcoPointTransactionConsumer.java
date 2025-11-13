package com.greenloop.reward.service;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import java.util.function.Consumer;

@Service
@Slf4j
@RequiredArgsConstructor
public class EcoPointTransactionConsumer {
    private final EcoPointUserService ecoPointUserService;

    @Bean
    public Consumer<EcoPointTransactionDTO> consumerUpdateEcoTransaction() {
        return transaction -> {
            log.info("Received EcoPointTransaction event: {}", transaction);
            ecoPointUserService.updateEcoPointUserBalance(transaction);
        };
    }
}
