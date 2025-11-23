package com.greenloop.product.consumer;

import com.greenloop.product.dto.event.OrderCheckedOutEvent;
import com.greenloop.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import java.util.function.Consumer;

@Service
@Slf4j
@RequiredArgsConstructor
public class OrderEventConsumer {

    private final ProductService productService;

    @Bean
    public Consumer<OrderCheckedOutEvent> orderCheckedOutConsumer() {
        return event -> {
            log.info("Received OrderCheckedOutEvent for orderId: {}, customerId: {}",
                    event.getOrderId(), event.getCustomerId());

            if (event.getProductStatusChanges() == null || event.getProductStatusChanges().isEmpty()) {
                log.warn("No product status changes to process");
                return;
            }

            event.getProductStatusChanges().forEach(change -> {
                try {
                    productService.updateProductStatus(
                            change.getProductId(),
                            change.getNewStatus()
                    );
                } catch (Exception e) {
                    log.error("Failed to update product {} status: {}",
                            change.getProductId(), e.getMessage(), e);
                }
            });
        };
    }
}
