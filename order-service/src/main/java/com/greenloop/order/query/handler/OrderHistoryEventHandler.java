package com.greenloop.order.query.handler;

import com.greenloop.order.command.event.OrderCreatedEvent;
import com.greenloop.order.command.event.OrderStatusUpdatedEvent;
import com.greenloop.order.command.event.ShippingStatusChangedEvent;
import com.greenloop.order.constant.OrderHistoryConstants;
import com.greenloop.order.entity.OrderHistory;
import com.greenloop.order.repository.OrderHistoryRepository;
import com.greenloop.order.util.ShippingStatusMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.config.ProcessingGroup;
import org.axonframework.eventhandling.EventHandler;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;


@Component
@ProcessingGroup("order-history")
@RequiredArgsConstructor
@Slf4j
public class OrderHistoryEventHandler {
    private final OrderHistoryRepository historyRepository;

    @EventHandler
    public void on(OrderCreatedEvent event) {
        OrderHistory history = OrderHistory.builder()
                .orderId(event.getOrderId())
                .eventType(OrderHistoryConstants.EventType.ORDER_CREATED)
                .description("Đơn hàng đã được tạo")
                .newValue(event.getOrderStatus().name())
                .reason("")
                .changedBy(event.getCustomerId())
                .changedByRole(OrderHistoryConstants.ChangedByRole.CUSTOMER)
                .build();
        historyRepository.save(history);
    }
    @EventHandler
    public void on(OrderStatusUpdatedEvent event) {
        String description;
        String changedByRole;
        if (event.getGoshipShipmentId() != null) {
            description = "Đã tạo vận đơn GoShip: " + event.getGoshipShipmentId();
            changedByRole = OrderHistoryConstants.ChangedByRole.STAFF;
        } else {
            description = "Trạng thái đơn hàng: " + event.getNewStatus().getDescription();
            changedByRole = OrderHistoryConstants.ChangedByRole.SYSTEM;
        }
        OrderHistory history = OrderHistory.builder()
                .orderId(event.getOrderId())
                .eventType(OrderHistoryConstants.EventType.ORDER_STATUS_CHANGED)
                .description(description)
                .oldValue(event.getOldStatus().name())
                .newValue(event.getNewStatus().name())
                .reason(event.getReason())
                .changedByRole(changedByRole)
                .build();

        historyRepository.save(history);
    }
    @EventListener
    @Transactional
    public void onShippingStatusChanged(ShippingStatusChangedEvent event) {
        String oldStatusText = event.getOldStatus() != null
                ? ShippingStatusMapper.getStatusText(event.getOldStatus())
                : "";
        String newStatusText = ShippingStatusMapper.getStatusText(event.getNewStatus());
        OrderHistory history = OrderHistory.builder()
                .orderId(event.getOrderId())
                .eventType(OrderHistoryConstants.EventType.SHIPPING_STATUS_CHANGED)
                .description(newStatusText)
                .oldValue(oldStatusText)
                .newValue(newStatusText)
                .changedByRole(OrderHistoryConstants.ChangedByRole.SYSTEM)
                .build();
        historyRepository.save(history);
    }
}
