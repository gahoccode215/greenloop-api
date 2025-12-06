package com.greenloop.product.consumer;

import com.greenloop.product.dto.event.OrderCancelledEvent;
import com.greenloop.product.dto.event.OrderCheckedOutEvent;
import com.greenloop.product.dto.event.OrderOfflineCreatedEvent;
import com.greenloop.product.enums.EventMappingStatus;
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
    public Consumer<OrderCheckedOutEvent> orderCheckedOutProductConsumer() {
        return event -> {
            log.info("Received OrderCheckedOutEvent for orderId: {}, customerId: {}",
                    event.getOrderId(), event.getCustomerId());

            if (event.getProductStatusChanges() == null || event.getProductStatusChanges().isEmpty()) {
                log.warn("No product status changes to process for online order");
                return;
            }

            event.getProductStatusChanges().forEach(change -> {
                try {
                    productService.updateProductStatus(
                            change.getProductId(),
                            change.getNewStatus()
                    );
                    log.info("Updated product {} to status: {} for online order",
                            change.getProductId(), change.getNewStatus());
                } catch (Exception e) {
                    log.error("Failed to update product {} status: {}",
                            change.getProductId(), e.getMessage(), e);
                }
            });
        };
    }

    @Bean
    public Consumer<OrderCancelledEvent> orderCancelledProductConsumer() {
        return event -> {
            log.info("Received OrderCancelledEvent for orderId: {}, reason: {}",
                    event.getOrderId(), event.getReason());

            if (event.getProductStatusChanges() == null || event.getProductStatusChanges().isEmpty()) {
                log.warn("No product status changes to process for cancelled order");
                return;
            }

            event.getProductStatusChanges().forEach(change -> {
                try {
                    productService.updateProductStatus(
                            change.getProductId(),
                            change.getNewStatus()
                    );
                    log.info("Returned product {} to AVAILABLE from cancelled order",
                            change.getProductId());
                } catch (Exception e) {
                    log.error("Failed to return product {} to AVAILABLE: {}",
                            change.getProductId(), e.getMessage(), e);
                }
            });
        };
    }


    @Bean
    public Consumer<OrderOfflineCreatedEvent> orderOfflineCreatedProductConsumer() {
        return event -> {
            log.info("Received OrderOfflineCreatedEvent for orderId: {}, orderCode: {}, eventId: {}",
                    event.getOrderId(), event.getOrderCode(), event.getEventId());

            if (event.getProductStatusChanges() == null || event.getProductStatusChanges().isEmpty()) {
                log.warn("No product status changes to process for offline order");
                return;
            }

            event.getProductStatusChanges().forEach(change -> {
                try {
                    // 1. Update Product status -> SOLD
                    productService.updateProductStatus(
                            change.getProductId(),
                            change.getNewStatus()
                    );
                    log.info("Updated product {} to status: {} for offline order",
                            change.getProductId(), change.getNewStatus());

                    // 2. Update EventProductMapping status -> SOLD_OUT
                    productService.updateProductEventMappingStatus(
                            change.getProductId(),
                            event.getEventId(),
                            EventMappingStatus.SOLD_OUT
                    );
                    log.info("Updated product {} mapping to SOLD_OUT for event {}",
                            change.getProductId(), event.getEventId());

                } catch (Exception e) {
                    log.error("Failed to update product {} status: {}",
                            change.getProductId(), e.getMessage(), e);
                }
            });
        };
    }

}
